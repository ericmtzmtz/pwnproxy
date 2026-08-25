"""Active crawl engine: BFS queue with depth/rate limits and path-only dedup.

Used by the crawler worker subprocess to crawl a target from seeds,
fetching pages directly and yielding flow dicts to be re-published.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import AsyncIterator, Optional
from urllib.parse import urlparse

from pwnproxy.services.crawler.extractor import extract_from_headers, extract_urls
from pwnproxy.services.crawler.fetcher import Fetcher, fetch_robots, is_disallowed, parse_robots_disallow
from pwnproxy.services.session.manager import ScopeConfig

logger = logging.getLogger(__name__)

_DEFAULT_DEPTH = 3
_DEFAULT_MAX_URLS = 1000
_DEFAULT_RATE_LIMIT = 10.0
_DEFAULT_CONCURRENCY = 5


@dataclass
class CrawlConfig:
    seeds: list[str]
    depth: int = _DEFAULT_DEPTH
    rate_limit: float = _DEFAULT_RATE_LIMIT
    concurrency: int = _DEFAULT_CONCURRENCY
    max_urls: int = _DEFAULT_MAX_URLS
    respect_robots: bool = False
    include_discovered: bool = False
    scan_while_crawl: bool = False


@dataclass
class CrawlStats:
    fetched: int = 0
    queued: int = 0
    discovered: int = 0
    errors: int = 0

    def to_dict(self) -> dict:
        return {
            "fetched": self.fetched,
            "queued": self.queued,
            "discovered": self.discovered,
            "errors": self.errors,
        }


@dataclass
class _QueueEntry:
    url: str
    depth: int


@dataclass
class CrawlEngine:
    """BFS crawl engine. Call ``run()`` to iterate; it yields flow dicts."""

    config: CrawlConfig
    scope: ScopeConfig
    verify: bool = False
    _visited: set[str] = field(default_factory=set)
    _visited_paths: set[str] = field(default_factory=set)
    _queue: asyncio.Queue[Optional[_QueueEntry]] = field(default_factory=asyncio.Queue)
    _stats: CrawlStats = field(default_factory=CrawlStats)
    _cancel: bool = False
    _disallow_paths: list[str] = field(default_factory=list)
    _content_type: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        for seed in self.config.seeds:
            self._queue.put_nowait(_QueueEntry(url=seed, depth=0))

    def _path_key(self, url: str) -> str:
        """Return the path of a URL without query, for path-only dedup."""
        parsed = urlparse(url)
        return parsed.path or "/"

    @staticmethod
    def _content_type_from_headers(headers: dict) -> str:
        for name, value in (headers or {}).items():
            if (name or "").lower() == "content-type":
                return value or ""
        return ""

    def _queue_candidate(self, url: str, current_depth: int) -> bool:
        """Try to enqueue *url*. Returns True if it was actually added."""
        if url in self._visited:
            return False
        if not self.scope.is_in_scope(url):
            return False
        path_key = self._path_key(url)
        if path_key in self._visited_paths:
            return False
        if self.config.respect_robots and self._disallow_paths:
            if is_disallowed(url, self._disallow_paths):
                return False
        next_depth = current_depth + 1
        if next_depth > self.config.depth:
            return False
        self._visited.add(url)
        self._visited_paths.add(path_key)
        self._queue.put_nowait(_QueueEntry(url=url, depth=next_depth))
        self._stats.queued += 1
        return True

    async def run(self, fetcher: Fetcher) -> AsyncIterator[dict]:
        """Crawl from seeds, yielding flow dicts for each fetched page."""
        if self.config.respect_robots:
            origin = self.config.seeds[0] if self.config.seeds else ""
            robots_text = await fetch_robots(origin, verify=self.verify)
            if robots_text:
                self._disallow_paths = parse_robots_disallow(robots_text)

        sem = asyncio.Semaphore(self.config.concurrency)

        async def _fetch_one(entry: _QueueEntry) -> Optional[tuple[dict, _QueueEntry]]:
            if self._cancel or self._stats.fetched >= self.config.max_urls:
                return None
            async with sem:
                if self._cancel:
                    return None
                flow = await fetcher.fetch(entry.url)
                if flow is None:
                    self._stats.errors += 1
                    return None
                self._stats.fetched += 1
                return (flow, entry)

        while not self._cancel and self._stats.fetched < self.config.max_urls:
            batch: list[_QueueEntry] = []
            while not self._queue.empty() and len(batch) < self.config.concurrency:
                try:
                    entry = self._queue.get_nowait()
                    if entry is None:
                        break
                    if entry.url in self._visited and entry.depth > 0:
                        continue
                    batch.append(entry)
                except asyncio.QueueEmpty:
                    break

            if not batch:
                break

            tasks = [asyncio.create_task(_fetch_one(e)) for e in batch]
            for coro in asyncio.as_completed(tasks):
                result = await coro
                if result is None:
                    continue
                flow, entry = result

                yield flow

                # Extract candidates from this page.
                headers = flow.get("response_headers") or {}
                body = flow.get("response_body") or ""
                ct = self._content_type_from_headers(headers)
                candidates: list[tuple[str, str]] = []
                if body:
                    candidates.extend(extract_urls(body, entry.url, content_type=ct))
                candidates.extend(extract_from_headers(headers, entry.url))

                seen_in_page: set[str] = set()
                for candidate_url, source in candidates:
                    if candidate_url in seen_in_page:
                        continue
                    seen_in_page.add(candidate_url)
                    if not self.scope.is_in_scope(candidate_url):
                        continue
                    path_key = self._path_key(candidate_url)
                    if path_key in self._visited_paths:
                        continue
                    if self.config.respect_robots and self._disallow_paths:
                        if is_disallowed(candidate_url, self._disallow_paths):
                            continue
                    next_depth = entry.depth + 1
                    if next_depth <= self.config.depth:
                        self._visited.add(candidate_url)
                        self._visited_paths.add(path_key)
                        self._queue.put_nowait(_QueueEntry(url=candidate_url, depth=next_depth))
                        self._stats.queued += 1
                        self._stats.discovered += 1

        # Drain sentinel
        self._queue.put_nowait(None)

    def cancel(self) -> None:
        self._cancel = True

    @property
    def stats(self) -> CrawlStats:
        return self._stats
