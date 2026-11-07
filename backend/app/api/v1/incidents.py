from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user, require_roles
from app.models.alert import Alert
from app.models.incident import Incident, IncidentStatus, IncidentTimeline
from app.models.indicator import Indicator
from app.models.user import User, UserRole
from app.schemas.incident import IncidentCreate, IncidentResponse, IncidentUpdate
from app.services.audit import record_audit

router = APIRouter(prefix="/incidents", tags=["Incidents"])

@router.get("", response_model=List[IncidentResponse])
def list_incidents(
    status: Optional[IncidentStatus] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Incident)
    if status:
        query = query.filter(Incident.status == status)
    return query.order_by(desc(Incident.created_at)).all()

@router.get("/{id}", response_model=IncidentResponse)
def get_incident(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    incident = db.query(Incident).filter(Incident.id == id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident

@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
def create_incident(
    data: IncidentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(
        UserRole.ADMIN,
        UserRole.INCIDENT_RESPONDER,
        UserRole.SOC_ANALYST
    ))
):
    incident = Incident(
        title=data.title,
        description=data.description,
        severity=data.severity,
        status=IncidentStatus.OPEN,
        lead_id=current_user.id,
        containment_checklist=[
            {"step": "Perform initial triage and scope impact", "done": True},
            {"step": "Isolate compromised assets", "done": False},
            {"step": "Block malicious IOCs on edge firewalls", "done": False},
            {"step": "Conduct eradication and system recovery", "done": False}
        ]
    )
    db.add(incident)
    db.flush()

    # Link indicators
    for ind_id in data.indicator_ids or []:
        ind = db.query(Indicator).filter(Indicator.id == ind_id).first()
        if ind:
            incident.indicators.append(ind)

    # Link alerts
    for alt_id in data.alert_ids or []:
        alt = db.query(Alert).filter(Alert.id == alt_id).first()
        if alt:
            incident.alerts.append(alt)

    # Initial timeline entry
    timeline = IncidentTimeline(
        incident_id=incident.id,
        event_type="incident_created",
        title="Incident Opened",
        description=f"Created by {current_user.username}",
        source_user=current_user.username
    )
    db.add(timeline)
    db.commit()
    db.refresh(incident)

    record_audit(
        db=db,
        action="INCIDENT_CREATED",
        entity_type="incident",
        entity_id=incident.id,
        actor=current_user,
        details={"title": incident.title}
    )

    return incident

@router.patch("/{id}", response_model=IncidentResponse)
def update_incident(
    id: str,
    data: IncidentUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(
        UserRole.ADMIN,
        UserRole.INCIDENT_RESPONDER
    ))
):
    incident = db.query(Incident).filter(Incident.id == id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    changes = {}
    if data.title is not None:
        incident.title = data.title
    if data.description is not None:
        incident.description = data.description
    if data.severity is not None:
        changes["severity"] = data.severity.value
        incident.severity = data.severity
    if data.containment_checklist is not None:
        incident.containment_checklist = data.containment_checklist

    if data.status is not None:
        changes["status_from"] = incident.status.value
        changes["status_to"] = data.status.value
        incident.status = data.status
        if data.status in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED]:
            incident.resolved_at = datetime.now(timezone.utc)

        # Log timeline step
        timeline = IncidentTimeline(
            incident_id=incident.id,
            event_type="status_changed",
            title=f"Incident status changed to {data.status.value.upper()}",
            description=f"Updated by {current_user.username}",
            source_user=current_user.username
        )
        db.add(timeline)

    db.commit()
    db.refresh(incident)

    record_audit(
        db=db,
        action="INCIDENT_UPDATED",
        entity_type="incident",
        entity_id=incident.id,
        actor=current_user,
        details=changes
    )

    return incident

@router.post("/{id}/timeline")
def add_timeline_entry(
    id: str,
    title: str,
    description: Optional[str] = None,
    event_type: str = "analyst_note",
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(
        UserRole.ADMIN,
        UserRole.INCIDENT_RESPONDER,
        UserRole.SOC_ANALYST
    ))
):
    incident = db.query(Incident).filter(Incident.id == id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    timeline = IncidentTimeline(
        incident_id=incident.id,
        event_type=event_type,
        title=title,
        description=description,
        source_user=current_user.username
    )
    db.add(timeline)
    db.commit()

    record_audit(
        db=db,
        action="INCIDENT_TIMELINE_APPENDED",
        entity_type="incident",
        entity_id=incident.id,
        actor=current_user,
        details={"title": title, "type": event_type}
    )

    return {"status": "success", "message": "Timeline entry recorded"}
