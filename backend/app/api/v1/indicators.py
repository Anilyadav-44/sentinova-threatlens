from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user, require_roles
from app.models.indicator import Indicator, IndicatorStatus, IndicatorType, Tag
from app.models.security_event import SecurityEvent
from app.models.user import User, UserRole
from app.schemas.indicator import (
    IndicatorCreate,
    IndicatorListResponse,
    IndicatorResponse,
    IndicatorUpdate,
)
from app.services.audit import record_audit

router = APIRouter(prefix="/indicators", tags=["Indicators"])

@router.get("", response_model=IndicatorListResponse)
def list_indicators(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    type: Optional[IndicatorType] = None,
    status: Optional[IndicatorStatus] = None,
    min_severity: Optional[int] = Query(None, ge=0, le=100),
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Indicator)

    if type:
        query = query.filter(Indicator.type == type)
    if status:
        query = query.filter(Indicator.status == status)
    if min_severity is not None:
        query = query.filter(Indicator.severity_score >= min_severity)
    if search:
        search_filter = f"%{search}%"
        query = query.filter(
            (Indicator.value.ilike(search_filter)) |
            (Indicator.description.ilike(search_filter))
        )

    total = query.count()
    items = query.order_by(desc(Indicator.severity_score), desc(Indicator.last_seen))\
                 .offset((page - 1) * page_size)\
                 .limit(page_size)\
                 .all()

    return IndicatorListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size
    )

@router.get("/{id}", response_model=IndicatorResponse)
def get_indicator(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    indicator = db.query(Indicator).filter(Indicator.id == id).first()
    if not indicator:
        raise HTTPException(status_code=404, detail="Indicator not found")

    # Also fetch internal sightings count dynamically
    internal_sightings = db.query(SecurityEvent).filter(
        (SecurityEvent.destination_ip == indicator.value) |
        (SecurityEvent.domain == indicator.value) |
        (SecurityEvent.file_hash == indicator.value)
    ).count()

    indicator.ioc_metadata = {
        **(indicator.ioc_metadata or {}),
        "internal_sightings_count": internal_sightings
    }
    return indicator

@router.post("", response_model=IndicatorResponse, status_code=status.HTTP_201_CREATED)
def create_indicator(
    data: IndicatorCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(
        UserRole.ADMIN,
        UserRole.SECURITY_ENGINEER,
        UserRole.SOC_ANALYST,
        UserRole.INCIDENT_RESPONDER
    ))
):
    existing = db.query(Indicator).filter(
        Indicator.value == data.value,
        Indicator.type == data.type
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="Indicator already exists")

    now = datetime.now(timezone.utc)
    indicator = Indicator(
        value=data.value.strip(),
        type=data.type,
        severity_score=data.severity_score,
        confidence=data.confidence,
        tlp=data.tlp,
        status=data.status,
        description=data.description,
        first_seen=now,
        last_seen=now
    )
    db.add(indicator)
    db.flush()

    for tag_name in data.tags or []:
        tag = db.query(Tag).filter(Tag.name == tag_name.lower().strip()).first()
        if not tag:
            tag = Tag(name=tag_name.lower().strip())
            db.add(tag)
            db.flush()
        indicator.tags.append(tag)

    db.commit()
    db.refresh(indicator)

    record_audit(
        db=db,
        action="INDICATOR_CREATED",
        entity_type="indicator",
        entity_id=indicator.id,
        actor=current_user,
        details={"value": indicator.value, "type": indicator.type.value}
    )

    return indicator

@router.patch("/{id}", response_model=IndicatorResponse)
def update_indicator(
    id: str,
    data: IndicatorUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(
        UserRole.ADMIN,
        UserRole.SECURITY_ENGINEER,
        UserRole.SOC_ANALYST,
        UserRole.INCIDENT_RESPONDER
    ))
):
    indicator = db.query(Indicator).filter(Indicator.id == id).first()
    if not indicator:
        raise HTTPException(status_code=404, detail="Indicator not found")

    changes = {}
    if data.status is not None:
        changes["status_from"] = indicator.status.value
        changes["status_to"] = data.status.value
        indicator.status = data.status

    if data.tlp is not None:
        changes["tlp_to"] = data.tlp.value
        indicator.tlp = data.tlp

    if data.description is not None:
        indicator.description = data.description

    db.commit()
    db.refresh(indicator)

    record_audit(
        db=db,
        action="INDICATOR_UPDATED",
        entity_type="indicator",
        entity_id=indicator.id,
        actor=current_user,
        details=changes
    )

    return indicator
