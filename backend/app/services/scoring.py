from datetime import datetime, timezone
from typing import Any, Dict


def calculate_severity_score(
    reputation_score: int,  # 0 to 100 from reputation feeds
    source_count: int,      # number of distinct feeds reporting this indicator
    last_seen: datetime,    # timestamp of most recent report
    internal_sightings: int # number of times seen in internal security events
) -> Dict[str, Any]:
    """
    Computes a reproducible 0–100 severity score based on PRD Section 4 & FR-13:
    - Base Reputation (40%)
    - Source Corroboration (25%)
    - Recency Decay (15%)
    - Internal Sightings Multiplier (20%)
    """
    # 1. Base Reputation (0-100 clamped)
    s_rep = max(0, min(100, reputation_score))

    # 2. Source Corroboration
    if source_count <= 0:
        c_src = 20
    elif source_count == 1:
        c_src = 45
    elif source_count == 2:
        c_src = 75
    else:
        c_src = 100

    # 3. Recency Decay
    now = datetime.now(timezone.utc)
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    age_days = (now - last_seen).total_seconds() / 86400.0

    if age_days <= 1:
        r_rec = 100
    elif age_days <= 7:
        r_rec = 80
    elif age_days <= 30:
        r_rec = 50
    else:
        r_rec = 20

    # 4. Internal Sightings Multiplier
    if internal_sightings <= 0:
        i_sight = 0
    elif internal_sightings == 1:
        i_sight = 60
    elif internal_sightings <= 5:
        i_sight = 85
    else:
        i_sight = 100

    # Weighted Composite: 40% + 25% + 15% + 20% = 100%
    weighted_score = (
        0.40 * s_rep +
        0.25 * c_src +
        0.15 * r_rec +
        0.20 * i_sight
    )

    final_score = int(round(max(0, min(100, weighted_score))))

    return {
        "score": final_score,
        "breakdown": {
            "reputation_component": round(0.40 * s_rep, 2),
            "source_component": round(0.25 * c_src, 2),
            "recency_component": round(0.15 * r_rec, 2),
            "internal_sightings_component": round(0.20 * i_sight, 2),
            "raw_inputs": {
                "base_reputation": s_rep,
                "source_count": source_count,
                "age_days": round(age_days, 1),
                "internal_sightings": internal_sightings
            }
        }
    }
