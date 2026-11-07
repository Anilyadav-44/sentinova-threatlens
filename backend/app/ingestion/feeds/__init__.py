from app.ingestion.feeds.abuseipdb import AbuseIPDBCollector
from app.ingestion.feeds.base import BaseFeedCollector
from app.ingestion.feeds.feodotracker import FeodoTrackerCollector
from app.ingestion.feeds.malwarebazaar import MalwareBazaarCollector
from app.ingestion.feeds.otx import OTXCollector
from app.ingestion.feeds.threatfox import ThreatFoxCollector
from app.ingestion.feeds.urlhaus import URLhausCollector

ALL_COLLECTORS = [
    AbuseIPDBCollector,
    URLhausCollector,
    MalwareBazaarCollector,
    ThreatFoxCollector,
    FeodoTrackerCollector,
    OTXCollector,
]

__all__ = [
    "BaseFeedCollector",
    "AbuseIPDBCollector",
    "URLhausCollector",
    "MalwareBazaarCollector",
    "ThreatFoxCollector",
    "FeodoTrackerCollector",
    "OTXCollector",
    "ALL_COLLECTORS",
]
