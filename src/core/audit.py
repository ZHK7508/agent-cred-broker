import hashlib
import json
from datetime import datetime, timezone
from typing import Literal

from src.core.database import SessionLocal, AuditRow


def _hash_record(record: dict, prev_hash: str) -> str:
    canonical = {k: record[k] for k in sorted(record)}
    canonical["prev_hash"] = prev_hash
    payload = json.dumps(canonical, default=str, sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()


def append(
    event_type: Literal["issued", "denied", "used", "revoked"],
    principal: str,
    agent_id: str,
    action: str = "",
    resource: str = "",
    purpose: str = "",
    decision_reason: str = "",
    token_jti: str | None = None,
) -> AuditRow:
    session = SessionLocal()
    try:
        last = session.query(AuditRow).order_by(AuditRow.id.desc()).first()
        prev_hash = last.record_hash if last else "0" * 64

        now = datetime.now(timezone.utc)
        record = {
            "timestamp": now.isoformat(),
            "event_type": event_type,
            "principal": principal,
            "agent_id": agent_id,
            "action": action,
            "resource": resource,
            "purpose": purpose,
            "decision_reason": decision_reason,
            "token_jti": token_jti or "",
        }
        record_hash = _hash_record(record, prev_hash)

        row = AuditRow(
            timestamp=now,
            event_type=event_type,
            principal=principal,
            agent_id=agent_id,
            action=action,
            resource=resource,
            purpose=purpose,
            decision_reason=decision_reason,
            token_jti=token_jti,
            prev_hash=prev_hash,
            record_hash=record_hash,
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        return row
    finally:
        session.close()


def verify_chain() -> tuple[bool, str]:
    session = SessionLocal()
    try:
        rows = session.query(AuditRow).order_by(AuditRow.id.asc()).all()
        prev_hash = "0" * 64
        for row in rows:
            if row.prev_hash != prev_hash:
                return False, f"chain break: prev_hash mismatch at record {row.id}"
            record = {
                "timestamp": row.timestamp.isoformat(),
                "event_type": row.event_type,
                "principal": row.principal,
                "agent_id": row.agent_id,
                "action": row.action or "",
                "resource": row.resource or "",
                "purpose": row.purpose or "",
                "decision_reason": row.decision_reason or "",
                "token_jti": row.token_jti or "",
            }
            expected_hash = _hash_record(record, prev_hash)
            if row.record_hash != expected_hash:
                return False, f"chain break: record_hash mismatch at record {row.id}"
            prev_hash = row.record_hash
        return True, f"chain intact across {len(rows)} records"
    finally:
        session.close()
