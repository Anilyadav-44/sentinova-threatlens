import csv
import io
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.indicator import Indicator, IndicatorStatus
from app.models.user import User
from app.services.audit import record_audit

router = APIRouter(prefix="/export", tags=["Exports & Standards"])

@router.get("/csv")
def export_csv(
    status: Optional[IndicatorStatus] = None,
    min_severity: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Indicator).filter(Indicator.severity_score >= min_severity)
    if status:
        query = query.filter(Indicator.status == status)
    indicators = query.all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id", "value", "type", "severity_score", "confidence", "tlp", "status", "first_seen", "last_seen", "tags"
    ])

    for ind in indicators:
        tag_str = ";".join([t.name for t in ind.tags])
        writer.writerow([
            ind.id, ind.value, ind.type.value, ind.severity_score, ind.confidence,
            ind.tlp.value, ind.status.value, ind.first_seen.isoformat(), ind.last_seen.isoformat(), tag_str
        ])

    record_audit(
        db=db,
        action="EXPORT_CSV_GENERATED",
        entity_type="export",
        actor=current_user,
        details={"count": len(indicators), "min_severity": min_severity}
    )

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=threatlens_indicators_{datetime.now().strftime('%Y%m%d')}.csv"}
    )

@router.get("/stix")
def export_stix21(
    min_severity: int = 60,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Exports active threat intelligence as standard STIX 2.1 JSON bundle (FR-24).
    """
    indicators = db.query(Indicator).filter(
        Indicator.severity_score >= min_severity,
        Indicator.status == IndicatorStatus.ACTIVE
    ).all()

    stix_objects = []
    bundle_id = f"bundle--{uuid.uuid4()}"

    for ind in indicators:
        # Map to STIX pattern
        if ind.type.value == "ip":
            pattern = f"[ipv4-addr:value = '{ind.value}']"
        elif ind.type.value == "domain":
            pattern = f"[domain-name:value = '{ind.value}']"
        elif ind.type.value == "url":
            pattern = f"[url:value = '{ind.value}']"
        elif ind.type.value == "hash_sha256":
            pattern = f"[file:hashes.'SHA-256' = '{ind.value}']"
        elif ind.type.value == "hash_md5":
            pattern = f"[file:hashes.MD5 = '{ind.value}']"
        else:
            pattern = f"[network-traffic:dst_ref.value = '{ind.value}']"

        stix_indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{ind.id}",
            "created": ind.first_seen.isoformat(),
            "modified": ind.last_seen.isoformat(),
            "name": f"{ind.type.value.upper()}: {ind.value}",
            "description": ind.description or f"Aggregated by Sentinova ThreatLens with severity {ind.severity_score}/100",
            "indicator_types": ["malicious-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": ind.first_seen.isoformat(),
            "confidence": ind.confidence,
            "labels": [t.name for t in ind.tags]
        }
        stix_objects.append(stix_indicator)

    record_audit(
        db=db,
        action="EXPORT_STIX_GENERATED",
        entity_type="export",
        actor=current_user,
        details={"count": len(indicators), "min_severity": min_severity}
    )

    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": stix_objects
    }
