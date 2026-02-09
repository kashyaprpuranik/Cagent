from typing import List

from fastapi import HTTPException
from sqlalchemy.orm import Session

from control_plane.models import AgentState
from control_plane.auth import TokenInfo


def verify_agent_access(token_info: TokenInfo, agent_id: str, db: Session):
    """Verify that a token has access to the specified agent."""
    if token_info.is_super_admin:
        return  # Super admin can access any agent

    if token_info.token_type == "admin":
        # Admin can only access agents in their tenant
        if token_info.tenant_id:
            agent = db.query(AgentState).filter(AgentState.agent_id == agent_id).first()
            if agent and agent.tenant_id != token_info.tenant_id:
                raise HTTPException(
                    status_code=403,
                    detail=f"Agent '{agent_id}' belongs to a different tenant"
                )
        return

    # Agent tokens can only access their own agent
    if token_info.agent_id != agent_id:
        raise HTTPException(
            status_code=403,
            detail=f"Token does not have access to agent '{agent_id}'"
        )


def get_tenant_agent_ids(db: Session, tenant_id: int) -> List[str]:
    """Get all agent IDs belonging to a tenant."""
    agents = db.query(AgentState.agent_id).filter(AgentState.tenant_id == tenant_id).all()
    return [a.agent_id for a in agents]


def get_audit_tenant_id(token_info: TokenInfo, db: Session, agent_state: AgentState = None) -> int:
    """Get the target tenant ID for audit logging.

    This is the tenant whose data was affected, NOT the authorizer.
    The authorizer is captured in the AuditTrail.user field.

    Priority:
    1. If agent_state is provided, use its tenant_id (action targeted an agent)
    2. If token has a tenant_id, use it (tenant-scoped admin action)
    """
    if agent_state and agent_state.tenant_id:
        return agent_state.tenant_id
    if token_info.tenant_id:
        return token_info.tenant_id
    raise ValueError("Cannot determine target tenant for audit log")
