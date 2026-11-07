from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.alert import AlertSeverity, AlertStatus


class AlertBase(BaseModel):
    title: str
    description: Optional[str] = None
    severity: AlertSeverity = AlertSeverity.MEDIUM
    status: AlertStatus = AlertStatus.NEW
    score: int = Field(default=50, ge=0, le=100)


class AlertUpdate(BaseModel):
    status: Optional[AlertStatus] = None
    assignee_id: Optional[str] = None


class AlertResponse(AlertBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    rule_name: str
    indicator_id: Optional[str] = None
    assignee_id: Optional[str] = None
    created_at: datetime
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    alert_metadata: Dict[str, Any] = Field(default_factory=dict)
