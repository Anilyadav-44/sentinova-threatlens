
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.ingestion.deduplicator import process_candidate_ioc
from app.ingestion.feeds.feodotracker import FeodoTrackerCollector
from app.ingestion.feeds.threatfox import ThreatFoxCollector
from app.ingestion.feeds.urlhaus import URLhausCollector
from app.models.indicator import Indicator, IndicatorSource, IndicatorType


@pytest.fixture
def db_session():
    """In-memory SQLite session for isolated unit tests."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(bind=engine)
    session = TestingSession()
    yield session
    session.close()


@pytest.mark.asyncio
async def test_urlhaus_collector():
    collector = URLhausCollector()
    results = await collector.fetch_and_parse()
    assert len(results) > 0
    first = results[0]
    assert "raw_value" in first
    assert first["type_hint"] == "url"
    assert first["confidence"] >= 50
    assert "urlhaus" in first["tags"]


@pytest.mark.asyncio
async def test_threatfox_collector():
    collector = ThreatFoxCollector()
    results = await collector.fetch_and_parse()
    assert len(results) > 0
    first = results[0]
    assert "raw_value" in first
    assert first["confidence"] >= 50
    assert "threatfox" in first["tags"]


@pytest.mark.asyncio
async def test_feodotracker_collector():
    collector = FeodoTrackerCollector()
    results = await collector.fetch_and_parse()
    assert len(results) > 0
    first = results[0]
    assert "raw_value" in first
    assert first["type_hint"] == "ip"
    assert first["confidence"] >= 90
    assert "feodotracker" in first["tags"]


@pytest.mark.asyncio
async def test_idempotent_deduplication_and_provenance(db_session):
    """
    Verifies that:
    1. Ingesting an indicator creates an Indicator and IndicatorSource record.
    2. Repeated ingestion of the same indicator DOES NOT create duplicate Indicator records.
    3. Multi-source ingestion correctly appends new provenance and recalculates aggregate confidence.
    """
    candidate_1 = {
        "raw_value": "198.51.100.44",
        "type_hint": "ip",
        "confidence": 80,
        "reference": "https://threatfox.abuse.ch/ioc/101/",
        "tags": ["cobalt-strike", "c2"],
        "description": "Cobalt Strike C2 Node",
        "raw_payload": {"port": 443},
        "attack_technique": "T1071.001"
    }

    # First ingestion
    ind1 = await process_candidate_ioc(db_session, "ThreatFox", candidate_1)
    assert ind1.value == "198.51.100.44"
    assert ind1.type == IndicatorType.IP
    assert ind1.confidence == 80
    initial_first_seen = ind1.first_seen

    # Count total indicators in DB
    total_iocs_1 = db_session.query(Indicator).count()
    assert total_iocs_1 == 1

    # Repeat ingestion from same feed (Idempotency test)
    candidate_repeat = dict(candidate_1)
    candidate_repeat["confidence"] = 85
    ind_repeat = await process_candidate_ioc(db_session, "ThreatFox", candidate_repeat)

    # Must still only be 1 record in DB
    total_iocs_after_repeat = db_session.query(Indicator).count()
    assert total_iocs_after_repeat == 1
    assert ind_repeat.id == ind1.id
    assert ind_repeat.first_seen == initial_first_seen

    # Second ingestion from a different feed (Feodo Tracker) for the same IP
    candidate_2 = {
        "raw_value": "198.51.100.44",
        "type_hint": "ip",
        "confidence": 95,
        "reference": "https://feodotracker.abuse.ch/browse/host/198.51.100.44/",
        "tags": ["botnet", "qakbot"],
        "description": "Feodo Botnet Node",
        "raw_payload": {"status": "online"},
        "attack_technique": "T1071.001"
    }

    ind2 = await process_candidate_ioc(db_session, "Feodo Tracker", candidate_2)

    # Must still be only 1 indicator record
    assert db_session.query(Indicator).count() == 1
    assert ind2.id == ind1.id

    # Must have 2 distinct sources in provenance
    sources = db_session.query(IndicatorSource).filter(IndicatorSource.indicator_id == ind2.id).all()
    assert len(sources) == 2
    feed_names = {s.feed_name for s in sources}
    assert feed_names == {"ThreatFox", "Feodo Tracker"}

    # Aggregate confidence should reflect multi-source corroboration boost
    assert ind2.confidence >= 90
    assert ind2.severity_score > 0
