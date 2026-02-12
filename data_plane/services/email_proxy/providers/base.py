"""
Abstract base class for email providers.

Concrete methods (send, list_messages, get_message, etc.) use the abstract
connect_imap()/connect_smtp() methods, so providers only implement connection logic.
"""

import imaplib
import re
import smtplib
import email
import email.utils
import email.policy
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders


def _sanitize_filename(filename: str) -> str:
    """Remove characters that could cause header injection or path traversal."""
    # Strip CR/LF (header injection), NUL, and path separators
    filename = re.sub(r'[\r\n\x00/\\]', '', filename)
    # Collapse to a reasonable length
    return filename[:255] if filename else "attachment"


def _escape_imap_string(value: str) -> str:
    """Escape a string for safe use inside IMAP double-quoted search criteria."""
    return value.replace('\\', '\\\\').replace('"', '\\"')

from config import EmailAccount

logger = logging.getLogger(__name__)


class EmailProvider(ABC):
    def __init__(self, account: EmailAccount):
        self.account = account

    @abstractmethod
    def connect_imap(self) -> imaplib.IMAP4_SSL:
        """Connect and authenticate to IMAP server. Returns authenticated connection."""
        ...

    @abstractmethod
    def connect_smtp(self) -> smtplib.SMTP:
        """Connect and authenticate to SMTP server. Returns authenticated connection."""
        ...

    @abstractmethod
    def refresh_credentials(self) -> bool:
        """Refresh OAuth tokens or similar. Returns True on success."""
        ...

    def send(
        self,
        to: list[str],
        subject: str,
        body: str = "",
        html: str = "",
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        attachments: list[dict] | None = None,
    ) -> str:
        """Send an email. Returns the Message-ID."""
        msg = MIMEMultipart("alternative")
        msg["From"] = self.account.email
        msg["To"] = ", ".join(to)
        msg["Subject"] = subject
        msg["Date"] = email.utils.formatdate(localtime=True)
        msg["Message-ID"] = email.utils.make_msgid()

        if cc:
            msg["Cc"] = ", ".join(cc)

        # Attach text and/or HTML parts
        if body:
            msg.attach(MIMEText(body, "plain"))
        if html:
            msg.attach(MIMEText(html, "html"))
        if not body and not html:
            msg.attach(MIMEText("", "plain"))

        # Attachments
        if attachments:
            # Convert to mixed multipart
            outer = MIMEMultipart("mixed")
            for key in msg.keys():
                outer[key] = msg[key]
            for part in msg.get_payload():
                outer.attach(part)

            for att in attachments:
                part = MIMEBase("application", "octet-stream")
                import base64
                part.set_payload(base64.b64decode(att["content_base64"]))
                encoders.encode_base64(part)
                part.add_header(
                    "Content-Disposition",
                    "attachment",
                    filename=_sanitize_filename(att.get("filename", "attachment")),
                )
                outer.attach(part)
            msg = outer

        all_recipients = list(to)
        if cc:
            all_recipients.extend(cc)
        if bcc:
            all_recipients.extend(bcc)

        smtp = self.connect_smtp()
        try:
            smtp.sendmail(self.account.email, all_recipients, msg.as_string())
            logger.info(f"Sent email to {all_recipients} via {self.account.name}")
            return msg["Message-ID"]
        finally:
            smtp.quit()

    def list_messages(
        self,
        folder: str = "INBOX",
        limit: int = 20,
        since: str | None = None,
        from_filter: str | None = None,
    ) -> list[dict]:
        """List messages from IMAP folder. Returns list of message summaries."""
        imap = self.connect_imap()
        try:
            status, _ = imap.select(folder, readonly=True)
            if status != "OK":
                raise RuntimeError(f"Failed to select folder: {folder}")

            # Build IMAP search criteria
            criteria = []
            if since:
                # Convert YYYY-MM-DD to IMAP date format (DD-Mon-YYYY)
                dt = datetime.strptime(since, "%Y-%m-%d")
                imap_date = dt.strftime("%d-%b-%Y")
                criteria.append(f'SINCE {imap_date}')
            if from_filter:
                criteria.append(f'FROM "{_escape_imap_string(from_filter)}"')

            search_str = " ".join(criteria) if criteria else "ALL"
            status, data = imap.search(None, search_str)
            if status != "OK":
                return []

            uids = data[0].split()
            # Take the most recent `limit` messages
            uids = uids[-limit:] if len(uids) > limit else uids

            messages = []
            for uid in reversed(uids):  # newest first
                status, msg_data = imap.fetch(uid, "(RFC822.HEADER)")
                if status != "OK" or not msg_data[0]:
                    continue
                raw = msg_data[0][1]
                msg = email.message_from_bytes(raw, policy=email.policy.default)

                # Extract snippet from subject as placeholder
                messages.append({
                    "uid": uid.decode(),
                    "from": msg.get("From", ""),
                    "to": msg.get("To", ""),
                    "subject": msg.get("Subject", ""),
                    "date": msg.get("Date", ""),
                    "snippet": msg.get("Subject", "")[:100],
                })

            return messages
        finally:
            imap.logout()

    def get_message(self, uid: str, folder: str = "INBOX") -> dict:
        """Get full message by UID."""
        imap = self.connect_imap()
        try:
            imap.select(folder, readonly=True)
            status, msg_data = imap.fetch(uid.encode(), "(RFC822)")
            if status != "OK" or not msg_data[0]:
                raise RuntimeError(f"Message {uid} not found")

            raw = msg_data[0][1]
            msg = email.message_from_bytes(raw, policy=email.policy.default)

            body_text = ""
            body_html = ""
            attachments = []

            if msg.is_multipart():
                for i, part in enumerate(msg.walk()):
                    content_type = part.get_content_type()
                    disposition = str(part.get("Content-Disposition", ""))

                    if "attachment" in disposition:
                        attachments.append({
                            "part_id": str(i),
                            "filename": part.get_filename() or f"attachment_{i}",
                            "content_type": content_type,
                            "size": len(part.get_payload(decode=True) or b""),
                        })
                    elif content_type == "text/plain" and not body_text:
                        body_text = part.get_content()
                    elif content_type == "text/html" and not body_html:
                        body_html = part.get_content()
            else:
                content_type = msg.get_content_type()
                if content_type == "text/html":
                    body_html = msg.get_content()
                else:
                    body_text = msg.get_content()

            return {
                "uid": uid,
                "from": msg.get("From", ""),
                "to": msg.get("To", ""),
                "cc": msg.get("Cc", ""),
                "subject": msg.get("Subject", ""),
                "date": msg.get("Date", ""),
                "body": body_text,
                "html": body_html,
                "attachments": attachments,
            }
        finally:
            imap.logout()

    def get_attachment(self, uid: str, part_id: str, folder: str = "INBOX") -> tuple[bytes, str, str]:
        """Download attachment by UID and part_id. Returns (data, filename, content_type)."""
        imap = self.connect_imap()
        try:
            imap.select(folder, readonly=True)
            status, msg_data = imap.fetch(uid.encode(), "(RFC822)")
            if status != "OK" or not msg_data[0]:
                raise RuntimeError(f"Message {uid} not found")

            raw = msg_data[0][1]
            msg = email.message_from_bytes(raw, policy=email.policy.default)

            for i, part in enumerate(msg.walk()):
                if str(i) == part_id:
                    data = part.get_payload(decode=True) or b""
                    filename = part.get_filename() or f"attachment_{i}"
                    content_type = part.get_content_type()
                    return data, filename, content_type

            raise RuntimeError(f"Attachment part_id {part_id} not found in message {uid}")
        finally:
            imap.logout()

    def list_folders(self) -> list[str]:
        """List IMAP folders."""
        imap = self.connect_imap()
        try:
            status, folders_raw = imap.list()
            if status != "OK":
                return []
            folders = []
            for item in folders_raw:
                if isinstance(item, bytes):
                    # Parse IMAP LIST response: (\\flags) "delimiter" "name"
                    decoded = item.decode()
                    # Extract folder name (last quoted string or last word)
                    parts = decoded.rsplit('"', 2)
                    if len(parts) >= 2:
                        folders.append(parts[-2])
                    else:
                        folders.append(decoded.split()[-1])
            return folders
        finally:
            imap.logout()
