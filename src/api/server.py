from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException

from src.core.models import CredentialRequest, CredentialResponse
from src.core.jwt_signer import mint, jwks
from src.core.policy import evaluate
from src.core import audit
from src.core.database import create_tables


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables()
    yield


app = FastAPI(title="Agent Credential Broker", lifespan=lifespan)


@app.post("/credentials", response_model=CredentialResponse)
def issue_credential(req: CredentialRequest):
    # TODO(production): verify req.user_token against real IdP
    decision = evaluate(req)

    if not decision.allowed:
        audit.append(
            event_type="denied",
            principal=req.principal,
            agent_id=req.agent_id,
            action=req.action,
            resource=req.resource,
            purpose=req.purpose,
            decision_reason=decision.reason,
        )
        raise HTTPException(status_code=403, detail=decision.reason)

    token, jti, expires_at = mint(
        principal=req.principal,
        agent_id=req.agent_id,
        action=req.action,
        resource=req.resource,
        ttl_seconds=req.ttl_seconds,
        purpose=req.purpose,
    )
    audit.append(
        event_type="issued",
        principal=req.principal,
        agent_id=req.agent_id,
        action=req.action,
        resource=req.resource,
        purpose=req.purpose,
        decision_reason=decision.reason,
        token_jti=jti,
    )
    return CredentialResponse(
        token=token,
        expires_at=expires_at,
        scope=f"{req.action} on {req.resource}",
    )


@app.get("/.well-known/jwks.json")
def get_jwks():
    return jwks()


@app.get("/audit/verify")
def verify_audit_chain():
    ok, message = audit.verify_chain()
    return {"chain_intact": ok, "message": message}


@app.get("/audit/records")
def list_audit_records(limit: int = 50):
    from src.core.database import SessionLocal, AuditRow
    session = SessionLocal()
    try:
        rows = session.query(AuditRow).order_by(AuditRow.id.desc()).limit(limit).all()
        return [
            {
                "id": r.id,
                "timestamp": r.timestamp.isoformat(),
                "event_type": r.event_type,
                "principal": r.principal,
                "agent_id": r.agent_id,
                "action": r.action,
                "resource": r.resource,
                "purpose": r.purpose,
                "decision_reason": r.decision_reason,
            }
            for r in rows
        ]
    finally:
        session.close()


@app.get("/health")
def health():
    return {"status": "ok"}
