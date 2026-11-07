import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

import httpx

from app.core.config import settings

logger = logging.getLogger("threatlens.ingestion")


class BaseFeedCollector(ABC):
    """
    Abstract Base Class for all ThreatLens external feed collectors.
    Handles network requests, timeout policies, error fallbacks, and standardizes
    the output schema for canonical normalization and deduplication.
    """

    def __init__(
        self,
        name: str,
        source_url: str,
        feed_format: str = "json",
        default_confidence: int = 70
    ):
        self.name = name
        self.source_url = source_url
        self.feed_format = feed_format
        self.default_confidence = default_confidence

    @abstractmethod
    async def fetch_and_parse(self) -> List[Dict[str, Any]]:
        """
        Fetches raw feed telemetry from the upstream source and returns
        a list of normalized candidate indicator dictionaries.

        Expected canonical candidate IOC dictionary schema:
        {
            "raw_value": str,            # The indicator value (IP, domain, URL, hash, CVE)
            "type_hint": Optional[str],  # Hint for type detection (ip, domain, url, etc.)
            "confidence": int,           # 0 to 100 source confidence
            "reference": Optional[str],  # Deep link to threat report or upstream source
            "tags": List[str],           # List of taxonomy and threat tags
            "description": str,          # Human-readable threat description
            "raw_payload": dict,         # Original raw record from upstream provider
            "attack_technique": Optional[str] # MITRE ATT&CK technique (e.g. T1071.001)
        }
        """
        pass

    async def _safe_http_get(
        self,
        url: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None
    ) -> Optional[httpx.Response]:
        """Performs a resilient HTTP GET request with timeouts and error catching."""
        target_url = url or self.source_url
        try:
            async with httpx.AsyncClient(
                timeout=settings.EXTERNAL_API_TIMEOUT,
                follow_redirects=True
            ) as client:
                response = await client.get(target_url, headers=headers, params=params)
                response.raise_for_status()
                return response
        except Exception as exc:
            logger.warning(f"[{self.name}] HTTP GET request to {target_url} failed: {exc}")
            return None

    async def _safe_http_post(
        self,
        url: Optional[str] = None,
        json_data: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Optional[httpx.Response]:
        """Performs a resilient HTTP POST request with timeouts and error catching."""
        target_url = url or self.source_url
        try:
            async with httpx.AsyncClient(
                timeout=settings.EXTERNAL_API_TIMEOUT,
                follow_redirects=True
            ) as client:
                response = await client.post(
                    target_url,
                    json=json_data,
                    data=data,
                    headers=headers
                )
                response.raise_for_status()
                return response
        except Exception as exc:
            logger.warning(f"[{self.name}] HTTP POST request to {target_url} failed: {exc}")
            return None
