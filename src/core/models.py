from datetime import datetime
from pydantic import BaseModel, Field
from typing import Literal


class CredentialRequest(BaseModel):
    principal: str           # user the agent is acting for
    agent_id: str
    action: str              # e.g. "s3:GetObject"
    resource: str            # e.g. "arn:aws:s3:::q3-reports/*"
    ttl_seconds: int = Field(default=300, ge=30, le=3600)
    purpose: str             # human-readable, logged for audit
    user_token: str          # IdP token proving authorization (stub: not verified in v1)


class CredentialResponse(BaseModel):
    token: str
    expires_at: datetime
    scope: str


class PolicyDecision(BaseModel):
    allowed: bool
    reason: str


class AuditRecord(BaseModel):
    id: int | None = None
    timestamp: datetime
    event_type: Literal["issued", "denied", "used", "revoked"]
    principal: str
    agent_id: str
    action: str
    resource: str
    purpose: str
    decision_reason: str
    token_jti: str | None
    prev_hash: str
    record_hash: str          # tamper-evident chain
