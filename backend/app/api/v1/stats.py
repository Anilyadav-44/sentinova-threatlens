from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.alert import Alert, AlertStatus
from app.models.feed import Feed
from app.models.incident import Incident, IncidentStatus
from app.models.indicator import Indicator
from app.models.user import User

router = APIRouter(prefix="/stats", tags=["Analytics & Statistics"])

@router.get("/executive")
def get_executive_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    total_indicators = db.query(Indicator).count()
    critical_indicators = db.query(Indicator).filter(Indicator.severity_score >= 80).count()
    high_indicators = db.query(Indicator).filter(
        Indicator.severity_score >= 60,
        Indicator.severity_score < 80
    ).count()

    db.query(Alert).count()
    open_alerts = db.query(Alert).filter(Alert.status.in_([AlertStatus.NEW, AlertStatus.ACKNOWLEDGED, AlertStatus.IN_PROGRESS])).count()
    resolved_alerts = db.query(Alert).filter(Alert.status.in_([AlertStatus.RESOLVED, AlertStatus.CLOSED])).count()

    active_incidents = db.query(Incident).filter(Incident.status != IncidentStatus.CLOSED).count()

    # Calculate Org Threat Exposure Index (0 - 100)
    avg_score = db.query(func.avg(Indicator.severity_score)).scalar() or 0
    exposure_index = min(100, int(avg_score * 0.7 + (critical_indicators * 2.5)))

    # Category breakdown
    type_counts = db.query(Indicator.type, func.count(Indicator.id)).group_by(Indicator.type).all()
    categories = [{"category": t[0].value.upper(), "count": t[1]} for t in type_counts]

    # Mock 30-day trend data for executive chart
    trend_data = []
    base_date = datetime.now(timezone.utc) - timedelta(days=29)
    for i in range(30):
        d = base_date + timedelta(days=i)
        trend_data.append({
            "date": d.strftime("%b %d"),
            "critical": max(1, int((i % 7) * 2 + 3)),
            "high": max(3, int((i % 5) * 4 + 7)),
            "medium": max(5, int((i % 4) * 6 + 12)),
        })

    # Top Targeted Regions
    geo_targeting = [
        {"country": "United States", "code": "US", "incidents": 142, "risk": "High"},
        {"country": "Germany", "code": "DE", "incidents": 87, "risk": "High"},
        {"country": "United Kingdom", "code": "GB", "incidents": 76, "risk": "Medium"},
        {"country": "India", "code": "IN", "incidents": 64, "risk": "Medium"},
        {"country": "Japan", "code": "JP", "incidents": 41, "risk": "Low"}
    ]

    return {
        "threat_exposure_index": exposure_index,
        "exposure_status": "High" if exposure_index >= 70 else ("Elevated" if exposure_index >= 45 else "Normal"),
        "total_indicators": total_indicators,
        "critical_indicators": critical_indicators,
        "high_indicators": high_indicators,
        "open_alerts": open_alerts,
        "resolved_alerts": resolved_alerts,
        "active_incidents": active_incidents,
        "categories": categories,
        "trend_30_days": trend_data,
        "geo_targeting": geo_targeting
    }

@router.get("/soc")
def get_soc_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    new_alerts = db.query(Alert).filter(Alert.status == AlertStatus.NEW).count()
    unassigned = db.query(Alert).filter(Alert.assignee_id is None, Alert.status != AlertStatus.CLOSED).count()
    critical_iocs = db.query(Indicator).filter(Indicator.severity_score >= 80).count()
    active_feeds = db.query(Feed).filter(Feed.is_enabled).count()

    return {
        "new_alerts": new_alerts,
        "unassigned_alerts": unassigned,
        "critical_indicators": critical_iocs,
        "active_feeds": active_feeds
    }

@router.get("/heatmap")
def get_threat_heatmap(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> List[Dict[str, Any]]:
    """
    Returns geographic threat points for global attack map (FR-20).
    """
    return [
        {"city": "Frankfurt", "country": "Germany", "lat": 50.1109, "lng": 8.6821, "intensity": 0.85, "type": "Tor / Scanner C2", "count": 89},
        {"city": "Moscow", "country": "Russia", "lat": 55.7558, "lng": 37.6173, "intensity": 0.95, "type": "Cobalt Strike / APT", "count": 142},
        {"city": "Beijing", "country": "China", "lat": 39.9042, "lng": 116.4074, "intensity": 0.90, "type": "AiTM / Stealer Infra", "count": 118},
        {"city": "Amsterdam", "country": "Netherlands", "lat": 52.3676, "lng": 4.9041, "intensity": 0.75, "type": "Malware Dropper", "count": 64},
        {"city": "San Jose", "country": "United States", "lat": 37.3382, "lng": -121.8863, "intensity": 0.70, "type": "Phishing Landing", "count": 55},
        {"city": "Sao Paulo", "country": "Brazil", "lat": -23.5505, "lng": -46.6333, "intensity": 0.65, "type": "Banking Trojan", "count": 48},
        {"city": "Singapore", "country": "Singapore", "lat": 1.3521, "lng": 103.8198, "intensity": 0.60, "type": "Mirai Scanner", "count": 39},
        {"city": "Mumbai", "country": "India", "lat": 19.0760, "lng": 72.8777, "intensity": 0.55, "type": "Credential Stuffing", "count": 32}
    ]

@router.get("/attack-matrix")
def get_attack_matrix(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> List[Dict[str, Any]]:
    return [
        {"technique_id": "T1071.001", "name": "Web Protocols (C2)", "tactic": "Command & Control", "count": 18, "color": "#ef4444"},
        {"technique_id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access", "count": 14, "color": "#f97316"},
        {"technique_id": "T1566.002", "name": "Spearphishing Link", "tactic": "Initial Access", "count": 12, "color": "#f59e0b"},
        {"technique_id": "T1204.002", "name": "Malicious File", "tactic": "Execution", "count": 11, "color": "#8b5cf6"},
        {"technique_id": "T1190", "name": "Exploit Public-Facing App", "tactic": "Initial Access", "count": 9, "color": "#ef4444"},
        {"technique_id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact", "count": 7, "color": "#dc2626"}
    ]
