from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.indicator import AttackTechnique, Indicator, IndicatorStatus, IndicatorType, Tag
from app.models.user import User
from app.schemas.indicator import IndicatorResponse

router = APIRouter(prefix="/search", tags=["Threat Hunting Search"])

@router.get("")
def search_threat_intel(
    q: Optional[str] = Query(None, description="Keyword, IP, Domain, or Hash search"),
    type: Optional[IndicatorType] = None,
    tag: Optional[str] = None,
    technique: Optional[str] = None,
    min_score: Optional[int] = Query(None, ge=0, le=100),
    status: Optional[IndicatorStatus] = None,
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    query = db.query(Indicator)

    if q:
        search_filter = f"%{q.strip()}%"
        query = query.filter(
            (Indicator.value.ilike(search_filter)) |
            (Indicator.description.ilike(search_filter))
        )

    if type:
        query = query.filter(Indicator.type == type)

    if status:
        query = query.filter(Indicator.status == status)

    if min_score is not None:
        query = query.filter(Indicator.severity_score >= min_score)

    if tag:
        query = query.join(Indicator.tags).filter(Tag.name == tag.lower().strip())

    if technique:
        query = query.join(Indicator.attack_techniques).filter(AttackTechnique.technique_id == technique)

    total_hits = query.count()
    results = query.order_by(desc(Indicator.severity_score), desc(Indicator.last_seen)).limit(limit).all()

    # Calculate Facets for Threat Hunter pivoting
    type_facets = db.query(Indicator.type, func.count(Indicator.id)).group_by(Indicator.type).all()
    status_facets = db.query(Indicator.status, func.count(Indicator.id)).group_by(Indicator.status).all()
    top_tags = db.query(Tag.name, func.count(Indicator.id))\
                 .join(Tag.indicators)\
                 .group_by(Tag.name)\
                 .order_by(desc(func.count(Indicator.id)))\
                 .limit(10)\
                 .all()

    return {
        "query": q,
        "total_hits": total_hits,
        "results": [IndicatorResponse.from_orm(r) for r in results],
        "facets": {
            "types": {t[0].value: t[1] for t in type_facets},
            "statuses": {s[0].value: s[1] for s in status_facets},
            "top_tags": {tag[0]: tag[1] for tag in top_tags}
        }
    }
