from datetime import datetime, timedelta, timezone

from app.services.scoring import calculate_severity_score


def test_scoring_within_bounds():
    now = datetime.now(timezone.utc)
    res = calculate_severity_score(
        reputation_score=100,
        source_count=5,
        last_seen=now,
        internal_sightings=10
    )
    assert 0 <= res["score"] <= 100
    assert res["score"] == 100

def test_scoring_weights_and_factors():
    now = datetime.now(timezone.utc)
    res = calculate_severity_score(
        reputation_score=80,
        source_count=1,
        last_seen=now,
        internal_sightings=0
    )
    # 0.40 * 80 (32) + 0.25 * 45 (11.25) + 0.15 * 100 (15) + 0.20 * 0 (0) = 58.25 -> 58
    assert res["score"] == 58
    assert "breakdown" in res
    assert res["breakdown"]["reputation_component"] == 32.0
    assert res["breakdown"]["internal_sightings_component"] == 0.0

def test_scoring_recency_decay():
    now = datetime.now(timezone.utc)
    fresh = calculate_severity_score(80, 2, now, 0)["score"]
    old = calculate_severity_score(80, 2, now - timedelta(days=45), 0)["score"]
    assert fresh > old

def test_scoring_internal_sightings_boost():
    now = datetime.now(timezone.utc)
    without_sightings = calculate_severity_score(70, 1, now, 0)["score"]
    with_sightings = calculate_severity_score(70, 1, now, 3)["score"]
    assert with_sightings > without_sightings
