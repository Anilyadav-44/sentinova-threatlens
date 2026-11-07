from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field


class FeedResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    display_name: str
    description: Optional[str] = None
    source_url: str
    feed_format: str
    poll_interval_minutes: int
    is_enabled: bool
    last_polled_at: Optional[datetime] = None
    last_status: str
    last_error_message: Optional[str] = None
    total_indicators_ingested: int
    feed_metadata: Dict[str, Any] = Field(default_factory=dict)


class FeedUpdate(BaseModel):
    is_enabled: Optional[bool] = None
    poll_interval_minutes: Optional[int] = None
