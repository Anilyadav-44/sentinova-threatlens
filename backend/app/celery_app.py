import asyncio
import logging

from celery import Celery

from app.core.config import settings
from app.core.database import SessionLocal

logger = logging.getLogger("threatlens.celery")

celery = Celery(
    "threatlens",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

celery.conf.update(
    timezone="UTC",
    enable_utc=True,
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    task_track_started=True,
    broker_connection_retry_on_startup=True,
    beat_schedule={
        "poll-urlhaus-periodic": {
            "task": "app.celery_app.poll_single_feed_task",
            "schedule": float(settings.FEED_POLL_INTERVAL_URLHAUS),
            "args": ("URLhaus",),
        },
        "poll-threatfox-periodic": {
            "task": "app.celery_app.poll_single_feed_task",
            "schedule": float(settings.FEED_POLL_INTERVAL_THREATFOX),
            "args": ("ThreatFox",),
        },
        "poll-feodotracker-periodic": {
            "task": "app.celery_app.poll_single_feed_task",
            "schedule": float(settings.FEED_POLL_INTERVAL_FEODO),
            "args": ("Feodo Tracker",),
        },
    },
)


@celery.task(name="app.celery_app.poll_single_feed_task", bind=True, max_retries=3)
def poll_single_feed_task(self, feed_name: str):
    """Celery task executing scheduled ingestion for a designated threat intelligence feed."""
    logger.info(f"[Celery Worker] Starting scheduled ingestion for feed: {feed_name}")
    from app.ingestion.manager import ingestion_manager

    db = SessionLocal()
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(ingestion_manager.poll_feed(db, feed_name))
        loop.close()
        logger.info(f"[Celery Worker] Completed ingestion for {feed_name}: {result}")
        return result
    except Exception as exc:
        logger.error(f"[Celery Worker] Feed polling error: {exc}")
        db.rollback()
        raise self.retry(exc=exc, countdown=60)
    finally:
        db.close()


@celery.task(name="app.celery_app.poll_all_feeds_task")
def poll_all_feeds_task():
    """Celery task executing ingestion across all enabled threat intelligence feeds."""
    logger.info("[Celery Worker] Starting batch ingestion across all enabled feeds")
    from app.ingestion.manager import ingestion_manager

    db = SessionLocal()
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(ingestion_manager.poll_all_enabled_feeds(db))
        loop.close()
        return results
    finally:
        db.close()
