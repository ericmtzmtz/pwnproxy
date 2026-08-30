"""Thin event publisher wrapping TcpBridgeServer with topic constants.

Every ``bridge.publish`` call in the crawler worker goes through here,
which ensures correct topic strings and keeps the publish surface area
small for future QoS tuning at the publisher level.
"""

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from pwnproxy.shared.bus.topics import (
    BRUTEFORCE_COMPLETED,
    BRUTEFORCE_FAILED,
    BRUTEFORCE_PROGRESS,
    BRUTEFORCE_STARTED,
    CRAWL_COMPLETED,
    CRAWL_FAILED,
    CRAWL_PROGRESS,
    CRAWL_STARTED,
    CRAWLER_URL,
)

if TYPE_CHECKING:
    from pwnproxy.shared.bus.transports.tcp_bridge import TcpBridgeServer

logger = logging.getLogger(__name__)


class EventPublisher:
    """Wraps ``TcpBridgeServer.publish`` with topic constants for the crawler."""

    def __init__(self, bridge: "TcpBridgeServer") -> None:
        self._bridge = bridge

    async def crawl_started(self, job_id: int | None) -> None:
        await self._bridge.publish(CRAWL_STARTED, {"job_id": job_id})

    async def crawl_progress(self, job_id: int | None, stats: dict) -> None:
        await self._bridge.publish(CRAWL_PROGRESS, {"job_id": job_id, **stats})

    async def crawl_completed(self, job_id: int | None, stats: dict) -> None:
        await self._bridge.publish(CRAWL_COMPLETED, {"job_id": job_id, **stats})

    async def crawl_failed(self, job_id: int | None, error: str) -> None:
        await self._bridge.publish(CRAWL_FAILED, {"job_id": job_id, "error": error})

    async def crawl_flow(self, flow_dict: dict) -> None:
        await self._bridge.publish("crawler.flow", flow_dict)

    async def bruteforce_started(self, job_id: int | None) -> None:
        await self._bridge.publish(BRUTEFORCE_STARTED, {"job_id": job_id})

    async def bruteforce_progress(self, job_id: int | None, stats: dict) -> None:
        await self._bridge.publish(BRUTEFORCE_PROGRESS, {"job_id": job_id, **stats})

    async def bruteforce_completed(self, job_id: int | None, stats: dict) -> None:
        await self._bridge.publish(BRUTEFORCE_COMPLETED, {"job_id": job_id, **stats})

    async def bruteforce_failed(self, job_id: int | None, error: str) -> None:
        await self._bridge.publish(BRUTEFORCE_FAILED, {"job_id": job_id, "error": error})

    async def discovered_url(self, record: dict) -> None:
        await self._bridge.publish(CRAWLER_URL, {
            **record,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
