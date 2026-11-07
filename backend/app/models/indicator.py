import enum
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    SmallInteger,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from app.core.database import Base
from app.models.base import TimeStampedModel


class IndicatorType(str, enum.Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    CVE = "cve"


class TLPMarking(str, enum.Enum):
    CLEAR = "clear"
    GREEN = "green"
    AMBER = "amber"
    RED = "red"


class IndicatorStatus(str, enum.Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    WHITELISTED = "whitelisted"
    UNDER_REVIEW = "under_review"


# Many-to-many relationship table between indicators and tags
indicator_tags_table = Table(
    "indicator_tags",
    Base.metadata,
    Column("indicator_id", String(36), ForeignKey("indicators.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", String(36), ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True),
)


class Tag(TimeStampedModel):
    __tablename__ = "tags"

    name = Column(String(100), unique=True, index=True, nullable=False)
    color = Column(String(20), default="#3b82f6")

    indicators = relationship("Indicator", secondary=indicator_tags_table, back_populates="tags")


class Indicator(TimeStampedModel):
    __tablename__ = "indicators"
    __table_args__ = (
        UniqueConstraint("value", "type", name="uq_indicator_value_type"),
    )

    value = Column(String(500), index=True, nullable=False)
    type = Column(Enum(IndicatorType), index=True, nullable=False)
    severity_score = Column(SmallInteger, default=0, index=True, nullable=False)  # 0 to 100
    confidence = Column(SmallInteger, default=50, nullable=False)                  # 0 to 100 aggregate
    tlp = Column(Enum(TLPMarking), default=TLPMarking.CLEAR, nullable=False)
    status = Column(Enum(IndicatorStatus), default=IndicatorStatus.ACTIVE, index=True, nullable=False)

    description = Column(Text, nullable=True)
    first_seen = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    last_seen = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    ioc_metadata = Column(JSON, default=dict)

    # Relationships
    sources = relationship("IndicatorSource", back_populates="indicator", cascade="all, delete-orphan")
    enrichments = relationship("Enrichment", back_populates="indicator", cascade="all, delete-orphan")
    attack_techniques = relationship("AttackTechnique", back_populates="indicator", cascade="all, delete-orphan")
    tags = relationship("Tag", secondary=indicator_tags_table, back_populates="indicators")


class IndicatorSource(TimeStampedModel):
    __tablename__ = "indicator_sources"

    indicator_id = Column(String(36), ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False, index=True)
    feed_name = Column(String(100), nullable=False, index=True)
    source_confidence = Column(SmallInteger, default=50, nullable=False)
    source_reference = Column(String(500), nullable=True)
    first_reported = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    last_reported = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    raw_payload = Column(JSON, default=dict)

    indicator = relationship("Indicator", back_populates="sources")


class Enrichment(TimeStampedModel):
    __tablename__ = "enrichments"

    indicator_id = Column(String(36), ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False, index=True)
    provider = Column(String(100), nullable=False)  # e.g. AbuseIPDB, VirusTotal, GeoIP
    verdict = Column(String(50), default="unknown")  # malicious, suspicious, clean, unknown
    score = Column(SmallInteger, default=0)
    data = Column(JSON, default=dict)
    expires_at = Column(DateTime(timezone=True), nullable=True)

    indicator = relationship("Indicator", back_populates="enrichments")


class IndicatorRelationship(TimeStampedModel):
    __tablename__ = "indicator_relationships"

    source_id = Column(String(36), ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False, index=True)
    target_id = Column(String(36), ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False, index=True)
    relationship_type = Column(String(50), nullable=False)  # resolves_to, communicates_with, drops, targets


class AttackTechnique(TimeStampedModel):
    __tablename__ = "attack_techniques"

    indicator_id = Column(String(36), ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False, index=True)
    technique_id = Column(String(50), nullable=False, index=True)  # e.g., T1071.001
    technique_name = Column(String(200), nullable=False)
    tactic = Column(String(100), nullable=False)

    indicator = relationship("Indicator", back_populates="attack_techniques")
