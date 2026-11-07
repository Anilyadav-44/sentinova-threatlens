import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Column, DateTime, String
from sqlalchemy.orm import synonym

from app.models.base import TimeStampedModel


class AuditLog(TimeStampedModel):
    """
    Append-only audit log table recording all state changes, administrative actions,
    and security operations across the ThreatLens platform.
    """
    __tablename__ = "audit_log"

    actor_id = Column(String(36), nullable=True, index=True)
    actor_username = Column(String(100), default="system", index=True, nullable=False)
    action = Column(String(100), nullable=False, index=True)  # IOC_CREATE, IOC_UPDATE, FEED_POLL, etc.
    resource_type = Column(String(50), nullable=False, index=True)  # indicator, alert, incident, feed, user
    resource_id = Column(String(100), nullable=True, index=True)
    correlation_id = Column(
        String(64),
        default=lambda: uuid.uuid4().hex,
        nullable=False,
        index=True
    )
    timestamp = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True
    )
    ip_address = Column(String(50), nullable=True)
    details = Column(JSON, default=dict, nullable=False)

    # Aliases for backward compatibility with legacy endpoints
    entity_type = synonym("resource_type")
    entity_id = synonym("resource_id")
