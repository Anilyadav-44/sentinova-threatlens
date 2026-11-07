from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user, require_roles
from app.ingestion.manager import ingestion_manager
from app.models.feed import Feed
from app.models.user import User, UserRole
from app.schemas.feed import FeedResponse, FeedUpdate
from app.services.audit import record_audit

router = APIRouter(prefix="/feeds", tags=["Threat Feeds"])

@router.get("", response_model=List[FeedResponse])
def list_feeds(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Ensure all registered collectors exist as records in the DB
    for name, collector in ingestion_manager.collectors.items():
        existing = db.query(Feed).filter(Feed.name == name).first()
        if not existing:
            feed = Feed(
                name=name,
                display_name=collector.name,
                source_url=collector.source_url,
                feed_format=collector.feed_format,
                is_enabled=True,
                last_status="idle"
            )
            db.add(feed)
    db.commit()
    return db.query(Feed).all()

@router.post("/{name}/poll")
async def poll_feed(
    name: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.SECURITY_ENGINEER))
):
    result = await ingestion_manager.poll_feed(db, name)
    record_audit(
        db=db,
        action="FEED_POLLED",
        entity_type="feed",
        entity_id=name,
        actor=current_user,
        details=result
    )
    return result

@router.post("/poll-all")
async def poll_all_feeds(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.SECURITY_ENGINEER))
):
    results = await ingestion_manager.poll_all_enabled_feeds(db)
    record_audit(
        db=db,
        action="ALL_FEEDS_POLLED",
        entity_type="feed",
        actor=current_user,
        details={"results": results}
    )
    return {"status": "completed", "results": results}

@router.patch("/{name}", response_model=FeedResponse)
def update_feed(
    name: str,
    data: FeedUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.SECURITY_ENGINEER))
):
    feed = db.query(Feed).filter(Feed.name == name).first()
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    changes = {}
    if data.is_enabled is not None:
        changes["is_enabled"] = data.is_enabled
        feed.is_enabled = data.is_enabled
    if data.poll_interval_minutes is not None:
        changes["poll_interval_minutes"] = data.poll_interval_minutes
        feed.poll_interval_minutes = data.poll_interval_minutes

    db.commit()
    db.refresh(feed)

    record_audit(
        db=db,
        action="FEED_CONFIG_UPDATED",
        entity_type="feed",
        entity_id=feed.id,
        actor=current_user,
        details=changes
    )
    return feed
