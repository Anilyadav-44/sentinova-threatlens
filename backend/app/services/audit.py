import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.models.audit import AuditLog
from app.models.user import User


def record_audit(
    db: Session,
    action: str,
    entity_type: str,
    entity_id: Optional[str] = None,
    actor: Optional[User] = None,
    ip_address: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    correlation_id: Optional[str] = None
) -> AuditLog:
    """
    Appends an immutable audit log entry for review, compliance, and SOC traceability.
    """
    log_entry = AuditLog(
        actor_id=actor.id if actor else None,
        actor_username=actor.username if actor else "system",
        action=action,
        resource_type=entity_type,
        resource_id=str(entity_id) if entity_id else None,
        correlation_id=correlation_id or uuid.uuid4().hex,
        timestamp=datetime.now(timezone.utc),
        ip_address=ip_address or "127.0.0.1",
        details=details or {}
    )
    db.add(log_entry)
    db.commit()
    return log_entry
