import enum
from datetime import datetime, timezone

from sqlalchemy import JSON, Column, DateTime, Enum, ForeignKey, String, Table, Text
from sqlalchemy.orm import relationship

from app.core.database import Base
from app.models.base import TimeStampedModel


class IncidentSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"

# Association tables
incident_indicators_table = Table(
    "incident_indicators",
    Base.metadata,
    Column("incident_id", String(36), ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("indicator_id", String(36), ForeignKey("indicators.id", ondelete="CASCADE"), primary_key=True),
)

incident_alerts_table = Table(
    "incident_alerts",
    Base.metadata,
    Column("incident_id", String(36), ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("alert_id", String(36), ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True),
)

class Incident(TimeStampedModel):
    __tablename__ = "incidents"

    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(Enum(IncidentSeverity), default=IncidentSeverity.MEDIUM, index=True, nullable=False)
    status = Column(Enum(IncidentStatus), default=IncidentStatus.OPEN, index=True, nullable=False)

    lead_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    containment_checklist = Column(JSON, default=list)
    resolved_at = Column(DateTime, nullable=True)

    lead = relationship("User")
    indicators = relationship("Indicator", secondary=incident_indicators_table)
    alerts = relationship("Alert", secondary=incident_alerts_table)
    timeline_entries = relationship("IncidentTimeline", back_populates="incident", cascade="all, delete-orphan", order_by="IncidentTimeline.timestamp")

class IncidentTimeline(TimeStampedModel):
    __tablename__ = "incident_timeline"

    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    event_type = Column(String(50), nullable=False)  # indicator_added, analyst_action, status_change, etc.
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    source_user = Column(String(100), default="System")
    entry_metadata = Column(JSON, default=dict)

    incident = relationship("Incident", back_populates="timeline_entries")
