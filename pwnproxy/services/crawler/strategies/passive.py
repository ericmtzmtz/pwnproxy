"""Passive crawl strategy: extract URLs from proxy feed events.

Moved from ``CrawlerWorker._process_passive`` and ``_publish_discovered``
without rewriting logic.  Both share the same extraction → filter → persist
→ publish pattern, so the shared helper ``extract_and_persist`` serves as
the single implementation for both passive feed events and active crawl
discovery.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from pwnproxy.services.crawler.extractor import extract_from_headers, extract_urls

if TYPE_CHECKING:
    from pwnproxy.services.crawler.events import EventPublisher
    from pwnproxy.services.crawler.storage import DiscoveredURLStorage
    from pwnproxy.services.session.manager import ScopeConfig

logger = logging.getLogger(__name__)

MAX_BODY_CHARS = 512 * 1024


def _content_type(headers: dict) -> str:
    for name, value in (headers or {}).items():
        if (name or "").lower() == "content-type":
            return value or ""
    return ""


async def extract_and_persist(
    flow_dict: dict,
    scope: "ScopeConfig",
    storage: "DiscoveredURLStorage",
    events: "EventPublisher",
) -> None:
    """Extract URLs from a flow dict, persist new ones, and publish events.

    Shared by both the passive feed handler and the active crawl's
    ``_publish_discovered``.
    """
    base_url = flow_dict.get("url") or ""
    method = flow_dict.get("method") or "GET"
    if not base_url or not scope.is_in_scope(base_url):
        return

    headers = flow_dict.get("response_headers") or {}
    body = flow_dict.get("response_body")
    candidates: list[tuple[str, str]] = []
    if body:
        body_str = body[:MAX_BODY_CHARS] if isinstance(body, str) else body
        candidates.extend(extract_urls(body_str, base_url, content_type=_content_type(headers)))
    candidates.extend(extract_from_headers(headers, base_url))

    seen: set[str] = set()
    for url, source in candidates:
        if url in seen:
            continue
        seen.add(url)
        if not scope.is_in_scope(url):
            continue
        new_id = await storage.save(url=url, source=source, method=method, base_url=base_url)
        if new_id is None:
            continue
        await events.discovered_url({
            "id": new_id,
            "url": url,
            "source": source,
            "method": method,
            "base_url": base_url,
        })


async def process_passive(
    data: dict,
    scope: "ScopeConfig",
    storage: "DiscoveredURLStorage",
    events: "EventPublisher",
) -> None:
    """Handle a single ``crawler.feed`` event from the proxy."""
    try:
        await extract_and_persist(data, scope, storage, events)
    except Exception:
        logger.exception("crawler feed processing failed")
