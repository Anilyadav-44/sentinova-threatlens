from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.indicator import IndicatorStatus, IndicatorType, TLPMarking


class TagResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    color: str


class IndicatorSourceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    feed_name: str
    source_confidence: int = Field(..., ge=0, le=100)
    source_reference: Optional[str] = None
    first_reported: datetime
    last_reported: datetime
    raw_payload: Dict[str, Any] = Field(default_factory=dict)


# Alias for backward compatibility
SourceResponse = IndicatorSourceResponse


class AttackTechniqueResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    technique_id: str
    technique_name: str
    tactic: str


class IndicatorBase(BaseModel):
    value: str
    type: IndicatorType
    severity_score: int = Field(default=0, ge=0, le=100)
    confidence: int = Field(default=50, ge=0, le=100)
    tlp: TLPMarking = TLPMarking.CLEAR
    status: IndicatorStatus = IndicatorStatus.ACTIVE
    description: Optional[str] = None


class IndicatorCreate(IndicatorBase):
    tags: Optional[List[str]] = Field(default_factory=list)


class IndicatorIngest(BaseModel):
    """
    Canonical IOC Ingestion Schema representing threat indicators
    arriving from automated feeds, TAXII channels, or manual analyst submission.
    """
    value: str
    type_hint: Optional[str] = None
    confidence: int = Field(default=60, ge=0, le=100)
    tlp: TLPMarking = TLPMarking.CLEAR
    status: IndicatorStatus = IndicatorStatus.ACTIVE
    description: Optional[str] = None
    feed_name: str
    source_reference: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    attack_technique: Optional[str] = None
    raw_payload: Dict[str, Any] = Field(default_factory=dict)


class IndicatorUpdate(BaseModel):
    status: Optional[IndicatorStatus] = None
    tlp: Optional[TLPMarking] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None


class IndicatorResponse(IndicatorBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime
    tags: List[TagResponse] = Field(default_factory=list)
    sources: List[IndicatorSourceResponse] = Field(default_factory=list)
    attack_techniques: List[AttackTechniqueResponse] = Field(default_factory=list)
    ioc_metadata: Dict[str, Any] = Field(default_factory=dict)


class IndicatorListResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    items: List[IndicatorResponse]
    total: int
    page: int
    page_size: int
