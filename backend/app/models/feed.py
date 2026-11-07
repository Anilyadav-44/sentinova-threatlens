from sqlalchemy import JSON, Boolean, Column, DateTime, Integer, String, Text

from app.models.base import TimeStampedModel


class Feed(TimeStampedModel):
    __tablename__ = "feeds"

    name = Column(String(100), unique=True, index=True, nullable=False)
    display_name = Column(String(150), nullable=False)
    description = Column(Text, nullable=True)
    source_url = Column(String(500), nullable=False)
    feed_format = Column(String(50), default="json")  # json, csv, stix, taxii
    poll_interval_minutes = Column(Integer, default=60, nullable=False)
    is_enabled = Column(Boolean, default=True, nullable=False)

    last_polled_at = Column(DateTime, nullable=True)
    last_status = Column(String(50), default="idle")  # idle, in_progress, success, error
    last_error_message = Column(Text, nullable=True)
    total_indicators_ingested = Column(Integer, default=0)
    feed_metadata = Column(JSON, default=dict)
