from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.core.websocket import ws_manager
from app.ingestion.normalizer import detect_indicator_type
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.indicator import (
    AttackTechnique,
    Indicator,
    IndicatorSource,
    IndicatorStatus,
    IndicatorType,
    Tag,
    TLPMarking,
)
from app.models.security_event import SecurityEvent
from app.services.scoring import calculate_severity_score


def calculate_aggregate_confidence(sources: List[IndicatorSource], default_conf: int = 50) -> int:
    """
    Calculates aggregated source confidence from all corroborated sources.
    Uses the weighted average of source confidences plus a multi-source corroboration bonus.
    """
    if not sources:
        return default_conf

    confidences = [s.source_confidence for s in sources]
    avg_conf = sum(confidences) / len(confidences)
    max_conf = max(confidences)

    # Multi-source corroboration bonus (up to +15% for multi-feed confirmation)
    corroboration_bonus = min(15, (len(sources) - 1) * 5)

    # Base is blend of highest individual confidence and mean confidence
    blended_base = (0.7 * max_conf) + (0.3 * avg_conf)
    aggregated = int(round(blended_base + corroboration_bonus))
    return max(0, min(100, aggregated))


async def process_candidate_ioc(
    db: Session,
    feed_name: str,
    candidate: Dict[str, Any]
) -> Indicator:
    """
    Normalizes, deduplicates, and enriches candidate threat indicators:
    1. Canonical normalization & type detection (IP, domain, URL, hash, CVE).
    2. Lookup existing indicator by (value, type) to guarantee idempotency.
    3. If indicator exists, update last_seen timestamp.
    4. Append or update source provenance with timestamp, confidence, and payload.
    5. Re-calculate aggregate confidence from all correlated sources.
    6. Re-calculate 0-100 dynamic severity score.
    7. Correlate with internal security events and promote critical threats to alerts.
    """
    raw_val = candidate.get("raw_value", "")
    type_hint = candidate.get("type_hint")

    detected_type, cleaned_value = detect_indicator_type(raw_val)
    if not detected_type and type_hint:
        try:
            detected_type = IndicatorType(type_hint.lower())
        except ValueError:
            pass

    if not detected_type:
        detected_type = IndicatorType.DOMAIN if "." in cleaned_value else IndicatorType.IP

    now = datetime.now(timezone.utc)
    candidate_conf = int(candidate.get("confidence", 60))
    candidate_conf = max(0, min(100, candidate_conf))

    # 1. Lookup existing canonical indicator (Idempotency guarantee)
    indicator: Optional[Indicator] = db.query(Indicator).filter(
        Indicator.value == cleaned_value,
        Indicator.type == detected_type
    ).first()

    if not indicator:
        indicator = Indicator(
            value=cleaned_value,
            type=detected_type,
            severity_score=0,
            confidence=candidate_conf,
            tlp=TLPMarking.CLEAR,
            status=IndicatorStatus.ACTIVE,
            description=candidate.get("description", f"Aggregated from {feed_name}"),
            first_seen=now,
            last_seen=now,
            ioc_metadata={"origin_feed": feed_name}
        )
        db.add(indicator)
        db.flush()
    else:
        # Existing indicator: update last_seen without creating duplicate record
        indicator.last_seen = now

    # 2. Update or insert Source Provenance
    source: Optional[IndicatorSource] = db.query(IndicatorSource).filter(
        IndicatorSource.indicator_id == indicator.id,
        IndicatorSource.feed_name == feed_name
    ).first()

    if source:
        source.last_reported = now
        source.source_confidence = max(source.source_confidence, candidate_conf)
        source.raw_payload = candidate.get("raw_payload", {})
        if candidate.get("reference"):
            source.source_reference = candidate.get("reference")
    else:
        source = IndicatorSource(
            indicator_id=indicator.id,
            feed_name=feed_name,
            source_confidence=candidate_conf,
            source_reference=candidate.get("reference"),
            first_reported=now,
            last_reported=now,
            raw_payload=candidate.get("raw_payload", {})
        )
        db.add(source)
    db.flush()

    # 3. Associate Tags without duplicates
    for tag_name in candidate.get("tags", []):
        clean_tag = tag_name.strip().lower()
        if not clean_tag:
            continue
        tag = db.query(Tag).filter(Tag.name == clean_tag).first()
        if not tag:
            tag = Tag(name=clean_tag)
            db.add(tag)
            db.flush()
        if tag not in indicator.tags:
            indicator.tags.append(tag)

    # 4. Associate ATT&CK Technique if provided
    technique_id = candidate.get("attack_technique")
    if technique_id:
        existing_technique = db.query(AttackTechnique).filter(
            AttackTechnique.indicator_id == indicator.id,
            AttackTechnique.technique_id == technique_id
        ).first()
        if not existing_technique:
            tech = AttackTechnique(
                indicator_id=indicator.id,
                technique_id=technique_id,
                technique_name=f"Technique {technique_id}",
                tactic="Command and Control" if "1071" in technique_id else "Initial Access"
            )
            db.add(tech)

    # 5. Re-calculate aggregate confidence from all sources
    all_sources: List[IndicatorSource] = db.query(IndicatorSource).filter(
        IndicatorSource.indicator_id == indicator.id
    ).all()
    indicator.confidence = calculate_aggregate_confidence(all_sources, default_conf=candidate_conf)

    # 6. Correlate with Internal Security Events
    correlated_events = db.query(SecurityEvent).filter(
        (SecurityEvent.destination_ip == cleaned_value) |
        (SecurityEvent.domain == cleaned_value) |
        (SecurityEvent.file_hash == cleaned_value)
    ).all()

    internal_sightings_count = len(correlated_events)
    for event in correlated_events:
        event.is_correlated = True
        event.matched_indicator_id = indicator.id

    # 7. Compute 0-100 Severity Score
    distinct_sources_count = len(all_sources)
    score_result = calculate_severity_score(
        reputation_score=indicator.confidence,
        source_count=distinct_sources_count,
        last_seen=indicator.last_seen,
        internal_sightings=internal_sightings_count
    )

    indicator.severity_score = score_result["score"]
    indicator.ioc_metadata = {
        **(indicator.ioc_metadata or {}),
        "scoring_breakdown": score_result["breakdown"],
        "internal_sightings": internal_sightings_count,
        "sources_count": distinct_sources_count
    }
    db.commit()

    # 8. Raise real-time Alert if high severity (score >= 70)
    if indicator.severity_score >= 70:
        alert_sev = AlertSeverity.CRITICAL if indicator.severity_score >= 85 else AlertSeverity.HIGH

        existing_alert = db.query(Alert).filter(
            Alert.indicator_id == indicator.id,
            Alert.status.in_([AlertStatus.NEW, AlertStatus.ACKNOWLEDGED, AlertStatus.IN_PROGRESS])
        ).first()

        if not existing_alert:
            new_alert = Alert(
                title=f"Threat Detected: {indicator.value} ({indicator.type.value.upper()})",
                description=f"{indicator.description}. Reported by {distinct_sources_count} source(s) with severity {indicator.severity_score}/100.",
                severity=alert_sev,
                status=AlertStatus.NEW,
                score=indicator.severity_score,
                rule_name="Dynamic High-Severity IOC Threshold",
                indicator_id=indicator.id,
                alert_metadata={
                    "sources": distinct_sources_count,
                    "internal_sightings": internal_sightings_count
                }
            )
            db.add(new_alert)
            db.commit()

            # Broadcast to WebSocket
            await ws_manager.broadcast("alerts.stream", {
                "event": "alert.new",
                "alert": {
                    "id": new_alert.id,
                    "title": new_alert.title,
                    "severity": new_alert.severity.value,
                    "score": new_alert.score,
                    "indicator_value": indicator.value,
                    "created_at": new_alert.created_at.isoformat()
                }
            })

    if indicator.severity_score >= 80:
        await ws_manager.broadcast("indicators.high_severity", {
            "event": "indicator.critical",
            "indicator": {
                "id": indicator.id,
                "value": indicator.value,
                "type": indicator.type.value,
                "severity_score": indicator.severity_score,
                "sources_count": distinct_sources_count
            }
        })

    return indicator
