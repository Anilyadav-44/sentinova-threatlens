from sqlalchemy import JSON, Boolean, Column, ForeignKey, String
from sqlalchemy.orm import relationship

from app.models.base import TimeStampedModel


class SecurityEvent(TimeStampedModel):
    __tablename__ = "security_events"

    source_system = Column(String(100), nullable=False, index=True)  # firewall, edr, proxy, ids
    event_type = Column(String(100), nullable=False, index=True)  # outbound_connection, dns_lookup, process_exec
    source_ip = Column(String(50), nullable=True)
    destination_ip = Column(String(50), nullable=True, index=True)
    domain = Column(String(255), nullable=True, index=True)
    url = Column(String(1000), nullable=True)
    file_hash = Column(String(128), nullable=True, index=True)
    user_identity = Column(String(100), nullable=True)

    is_correlated = Column(Boolean, default=False, index=True)
    matched_indicator_id = Column(String(36), ForeignKey("indicators.id", ondelete="SET NULL"), nullable=True, index=True)
    raw_event = Column(JSON, default=dict)

    matched_indicator = relationship("Indicator")
