"""
Email Proxy - FastAPI service providing controlled email access for AI agents.

Supports Gmail (OAuth2), Outlook/M365 (OAuth2), and generic IMAP/SMTP (password).
Enforces address allowlists and rate limits per account.
"""

import logging
import json
import re
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, Response
from pydantic import BaseModel

from config import load_email_config, EmailAccount
from providers import create_provider
from providers.base import EmailProvider
from policy import check_recipients_allowed, check_sender_allowed, rate_limiter


def _sanitize_filename(filename: str) -> str:
    """Remove characters that could cause header injection or path traversal."""
    return re.sub(r'[\r\n\x00/\\]', '', filename)[:255] or "attachment"

# JSON logging to stdout
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter(
    json.dumps({
        "timestamp": "%(asctime)s",
        "level": "%(levelname)s",
        "logger": "%(name)s",
        "message": "%(message)s",
    })
))
logging.basicConfig(level=logging.INFO, handlers=[handler])
logger = logging.getLogger("email_proxy")

# Global state
accounts: dict[str, EmailAccount] = {}
providers: dict[str, EmailProvider] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load config and initialize providers on startup."""
    account_list = load_email_config()
    for acct in account_list:
        accounts[acct.name] = acct
        try:
            providers[acct.name] = create_provider(acct)
            logger.info(f"Initialized provider for account: {acct.name}")
        except Exception as e:
            logger.error(f"Failed to initialize provider for {acct.name}: {e}")
    logger.info(f"Email proxy started with {len(providers)} account(s)")
    yield
    accounts.clear()
    providers.clear()


app = FastAPI(title="Email Proxy", lifespan=lifespan)


# =========================================================================
# Pydantic Models
# =========================================================================

class SendRequest(BaseModel):
    account: str
    to: list[str]
    subject: str
    body: str = ""
    html: str = ""
    cc: list[str] | None = None
    bcc: list[str] | None = None
    attachments: list[dict] | None = None


class SendResponse(BaseModel):
    status: str
    message_id: str


class FoldersRequest(BaseModel):
    account: str


# =========================================================================
# Helpers
# =========================================================================

def _get_provider(account_name: str) -> tuple[EmailProvider, EmailAccount]:
    """Get provider and account by name, or raise 404."""
    if account_name not in providers:
        raise HTTPException(status_code=404, detail=f"Account not found: {account_name}")
    return providers[account_name], accounts[account_name]


# =========================================================================
# Endpoints
# =========================================================================

@app.get("/health")
def health():
    return {"status": "ok", "accounts": len(providers)}


@app.get("/accounts")
def list_accounts():
    """List configured accounts (no credentials exposed)."""
    return {
        "accounts": [
            {
                "name": acct.name,
                "provider": acct.provider,
                "email": acct.email,
                "imap_server": acct.imap_server,
                "smtp_server": acct.smtp_server,
            }
            for acct in accounts.values()
        ]
    }


@app.post("/send", response_model=SendResponse)
def send_email(req: SendRequest):
    """Send an email through the specified account."""
    provider, acct = _get_provider(req.account)

    # Policy: check recipients
    all_recipients = list(req.to)
    if req.cc:
        all_recipients.extend(req.cc)
    if req.bcc:
        all_recipients.extend(req.bcc)

    disallowed = check_recipients_allowed(all_recipients, acct.policy)
    if disallowed:
        raise HTTPException(
            status_code=403,
            detail=f"Recipients not allowed by policy: {', '.join(disallowed)}"
        )

    # Policy: rate limit
    if not rate_limiter.check(acct.name, "send", acct.policy):
        raise HTTPException(
            status_code=429,
            detail=f"Send rate limit exceeded for account {acct.name} ({acct.policy.sends_per_hour}/hour)"
        )

    try:
        message_id = provider.send(
            to=req.to,
            subject=req.subject,
            body=req.body,
            html=req.html,
            cc=req.cc,
            bcc=req.bcc,
            attachments=req.attachments,
        )
        return SendResponse(status="sent", message_id=message_id)
    except Exception as e:
        logger.error(f"Send failed for {req.account}: {e}")
        raise HTTPException(status_code=502, detail=f"Send failed: {e}")


@app.get("/inbox")
def list_inbox(
    account: str = Query(...),
    folder: str = Query("INBOX"),
    limit: int = Query(20, ge=1, le=100),
    since: str | None = Query(None),
    from_filter: str | None = Query(None),
):
    """List messages from an IMAP folder."""
    provider, acct = _get_provider(account)

    # Policy: rate limit
    if not rate_limiter.check(acct.name, "read", acct.policy):
        raise HTTPException(
            status_code=429,
            detail=f"Read rate limit exceeded for account {acct.name} ({acct.policy.reads_per_hour}/hour)"
        )

    try:
        messages = provider.list_messages(
            folder=folder, limit=limit, since=since, from_filter=from_filter,
        )

        # Policy: filter by allowed senders
        filtered = [
            msg for msg in messages
            if check_sender_allowed(msg.get("from", ""), acct.policy)
        ]

        return {"messages": filtered}
    except Exception as e:
        logger.error(f"Inbox list failed for {account}: {e}")
        raise HTTPException(status_code=502, detail=f"Failed to list messages: {e}")


@app.get("/message/{uid}")
def get_message(
    uid: str,
    account: str = Query(...),
    folder: str = Query("INBOX"),
):
    """Get a full message by UID."""
    provider, acct = _get_provider(account)

    if not rate_limiter.check(acct.name, "read", acct.policy):
        raise HTTPException(
            status_code=429,
            detail=f"Read rate limit exceeded for account {acct.name}"
        )

    try:
        message = provider.get_message(uid=uid, folder=folder)

        # Policy: check sender allowed
        if not check_sender_allowed(message.get("from", ""), acct.policy):
            raise HTTPException(status_code=403, detail="Sender not in allowed list")

        return message
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get message failed for {account}/{uid}: {e}")
        raise HTTPException(status_code=502, detail=f"Failed to get message: {e}")


@app.get("/attachment/{uid}/{part_id}")
def get_attachment(
    uid: str,
    part_id: str,
    account: str = Query(...),
    folder: str = Query("INBOX"),
):
    """Download an attachment by message UID and part ID."""
    provider, acct = _get_provider(account)

    if not rate_limiter.check(acct.name, "read", acct.policy):
        raise HTTPException(
            status_code=429,
            detail=f"Read rate limit exceeded for account {acct.name}"
        )

    try:
        data, filename, content_type = provider.get_attachment(
            uid=uid, part_id=part_id, folder=folder,
        )
        return Response(
            content=data,
            media_type=content_type,
            headers={"Content-Disposition": f'attachment; filename="{_sanitize_filename(filename)}"'},
        )
    except Exception as e:
        logger.error(f"Attachment download failed for {account}/{uid}/{part_id}: {e}")
        raise HTTPException(status_code=502, detail=f"Failed to download attachment: {e}")


@app.post("/folders")
def list_folders(req: FoldersRequest):
    """List IMAP folders for an account."""
    provider, acct = _get_provider(req.account)

    if not rate_limiter.check(acct.name, "read", acct.policy):
        raise HTTPException(
            status_code=429,
            detail=f"Read rate limit exceeded for account {acct.name}"
        )

    try:
        folders = provider.list_folders()
        return {"folders": folders}
    except Exception as e:
        logger.error(f"List folders failed for {req.account}: {e}")
        raise HTTPException(status_code=502, detail=f"Failed to list folders: {e}")
