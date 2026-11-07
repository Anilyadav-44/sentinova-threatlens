from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user, require_roles
from app.core.websocket import ws_manager
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.incident import Incident, IncidentSeverity, IncidentStatus, IncidentTimeline
from app.models.user import User, UserRole
from app.schemas.alert import AlertResponse, AlertUpdate
from app.services.audit import record_audit

router = APIRouter(prefix="/alerts", tags=["Alerts"])

@router.get("", response_model=List[AlertResponse])
def list_alerts(
    status: Optional[AlertStatus] = None,
    severity: Optional[AlertSeverity] = None,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Alert)
    if status:
        query = query.filter(Alert.status == status)
    if severity:
        query = query.filter(Alert.severity == severity)

    return query.order_by(desc(Alert.score), desc(Alert.created_at)).limit(limit).all()

@router.patch("/{id}", response_model=AlertResponse)
async def update_alert(
    id: str,
    data: AlertUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(
        UserRole.ADMIN,
        UserRole.SECURITY_ENGINEER,
        UserRole.SOC_ANALYST,
        UserRole.INCIDENT_RESPONDER
    ))
):
    alert = db.query(Alert).filter(Alert.id == id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    changes = {}
    now = datetime.now(timezone.utc)

    if data.status is not None:
        changes["status_from"] = alert.status.value
        changes["status_to"] = data.status.value
        alert.status = data.status
        if data.status == AlertStatus.ACKNOWLEDGED and not alert.acknowledged_at:
            alert.acknowledged_at = now
        elif data.status in [AlertStatus.RESOLVED, AlertStatus.CLOSED] and not alert.resolved_at:
            alert.resolved_at = now

    if data.assignee_id is not None:
        changes["assignee_id"] = data.assignee_id
        alert.assignee_id = data.assignee_id

    db.commit()
    db.refresh(alert)

    record_audit(
        db=db,
        action="ALERT_TRIAGED",
        entity_type="alert",
        entity_id=alert.id,
        actor=current_user,
        details=changes
    )

    await ws_manager.broadcast("alerts.stream", {
        "event": "alert.updated",
        "alert_id": alert.id,
        "status": alert.status.value,
        "assignee_id": alert.assignee_id
    })

    return alert

@router.post("/{id}/escalate")
async def escalate_alert_to_incident(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(
        UserRole.ADMIN,
        UserRole.SOC_ANALYST,
        UserRole.INCIDENT_RESPONDER
    ))
):
    alert = db.query(Alert).filter(Alert.id == id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Create new Incident from Alert
    incident = Incident(
        title=f"Incident: {alert.title}",
        description=alert.description,
        severity=IncidentSeverity.CRITICAL if alert.severity == AlertSeverity.CRITICAL else IncidentSeverity.HIGH,
        status=IncidentStatus.INVESTIGATING,
        lead_id=current_user.id,
        containment_checklist=[
            {"step": "Verify IOC sightings in network telemetry", "done": True},
            {"step": "Isolate affected host / drop at perimeter", "done": False},
            {"step": "Extract memory and forensic artifacts", "done": False},
            {"step": "Review lateral movement indicators", "done": False}
        ]
    )
    db.add(incident)
    db.flush()

    incident.alerts.append(alert)
    if alert.indicator:
        incident.indicators.append(alert.indicator)

    # Initial timeline event
    timeline_entry = IncidentTimeline(
        incident_id=incident.id,
        event_type="incident_escalated",
        title=f"Incident opened from alert '{alert.title}'",
        description=f"Escalated by {current_user.username} ({current_user.role.value}).",
        source_user=current_user.username
    )
    db.add(timeline_entry)

    # Update alert state
    alert.status = AlertStatus.IN_PROGRESS
    db.commit()

    record_audit(
        db=db,
        action="INCIDENT_ESCALATED_FROM_ALERT",
        entity_type="incident",
        entity_id=incident.id,
        actor=current_user,
        details={"alert_id": alert.id}
    )

    return {
        "status": "success",
        "incident_id": incident.id,
        "message": "Alert successfully escalated to active incident"
    }
