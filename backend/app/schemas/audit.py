from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class AuditLogBase(BaseModel):
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    correlation_id: str
    details: Dict[str, Any] = Field(default_factory=dict)
    actor_id: Optional[str] = None
    actor_username: str = "system"
    ip_address: Optional[str] = None


class AuditLogCreate(AuditLogBase):
    pass


class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    actor_id: Optional[str] = None
    actor_username: str
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    correlation_id: str
    timestamp: datetime
    created_at: datetime
    ip_address: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)

    # Backward compatibility aliases
    @property
    def entity_type(self) -> str:
        return self.resource_type

    @property
    def entity_id(self) -> Optional[str]:
        return self.resource_id


class AuditLogListResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    items: List[AuditLogResponse]
    total: int
