import enum

from sqlalchemy import JSON, Boolean, Column, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.models.base import TimeStampedModel


class AlertSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class AlertStatus(str, enum.Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"

class Alert(TimeStampedModel):
    __tablename__ = "alerts"

    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(Enum(AlertSeverity), default=AlertSeverity.MEDIUM, index=True, nullable=False)
    status = Column(Enum(AlertStatus), default=AlertStatus.NEW, index=True, nullable=False)
    score = Column(Integer, default=50, index=True, nullable=False)

    rule_name = Column(String(100), default="Default Severity Rule")
    indicator_id = Column(String(36), ForeignKey("indicators.id", ondelete="SET NULL"), nullable=True, index=True)
    assignee_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)

    acknowledged_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    alert_metadata = Column(JSON, default=dict)

    indicator = relationship("Indicator")
    assignee = relationship("User")

class AlertRule(TimeStampedModel):
    __tablename__ = "alert_rules"

    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    severity_threshold = Column(Integer, default=70)
    category = Column(String(50), default="all")
    is_enabled = Column(Boolean, default=True)
    routing_role = Column(String(50), default="soc_analyst")
