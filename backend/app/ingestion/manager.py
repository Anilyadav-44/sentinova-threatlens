import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from sqlalchemy.orm import Session

from app.ingestion.deduplicator import process_candidate_ioc
from app.ingestion.feeds import ALL_COLLECTORS
from app.models.feed import Feed

logger = logging.getLogger("threatlens.ingestion")

class IngestionManager:
    def __init__(self):
        self.collectors = {cls().name: cls() for cls in ALL_COLLECTORS}

    async def poll_feed(self, db: Session, feed_name: str) -> Dict[str, Any]:
        collector = self.collectors.get(feed_name)
        if not collector:
            return {"error": f"Collector for {feed_name} not found"}

        feed_record = db.query(Feed).filter(Feed.name == feed_name).first()
        if not feed_record:
            feed_record = Feed(
                name=feed_name,
                display_name=collector.name,
                source_url=collector.source_url,
                feed_format=collector.feed_format,
                is_enabled=True,
                last_status="in_progress"
            )
            db.add(feed_record)
        else:
            feed_record.last_status = "in_progress"
        db.commit()

        start_time = datetime.now(timezone.utc)
        ingested_count = 0
        error_msg = None

        try:
            candidates = await collector.fetch_and_parse()
            for cand in candidates:
                await process_candidate_ioc(db, feed_name, cand)
                ingested_count += 1

            feed_record.last_status = "success"
            feed_record.total_indicators_ingested += ingested_count
            feed_record.last_polled_at = datetime.now(timezone.utc)
            feed_record.last_error_message = None
            db.commit()
            logger.info(f"Feed {feed_name} successfully ingested {ingested_count} indicators.")
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error during feed {feed_name} ingestion: {e}")
            feed_record.last_status = "error"
            feed_record.last_error_message = error_msg
            feed_record.last_polled_at = datetime.now(timezone.utc)
            db.commit()

        return {
            "feed": feed_name,
            "status": "success" if not error_msg else "error",
            "ingested_count": ingested_count,
            "error": error_msg,
            "duration_seconds": round((datetime.now(timezone.utc) - start_time).total_seconds(), 2)
        }

    async def poll_all_enabled_feeds(self, db: Session) -> List[Dict[str, Any]]:
        results = []
        for name in self.collectors.keys():
            res = await self.poll_feed(db, name)
            results.append(res)
        return results

ingestion_manager = IngestionManager()
