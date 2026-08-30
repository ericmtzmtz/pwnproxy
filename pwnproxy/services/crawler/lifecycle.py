"""Crawler job lifecycle config types.

The state machine itself lives in ``JobLifecycle`` (``services/jobs/lifecycle.py``),
which owns the JobState transitions (start/stop/complete/fail/recover).  This
module holds the *config dataclasses* that feed-event messages parse into —
the typed boundary between the message bus and the strategy functions.

The start/stop message handlers remain in ``CrawlerWorker`` (the coordinator):
they share the worker's mutable state dict and are exercised directly by the
E2E tests, so extracting them into a class with a single consumer would add
an abstraction with no real users (design rule: no abstractions until 2
real consumers).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CrawlStartConfig:
    seeds: list[str]
    depth: int = 3
    rate_limit: float = 10.0
    concurrency: int = 5
    max_urls: int = 1000
    respect_robots: bool = False
    include_discovered: bool = False
    scan_while_crawl: bool = False


@dataclass
class BruteforceStartConfig:
    base_urls: list[str]
    wordlist: list[str]
    extensions: list[str] = field(default_factory=list)
    status_filter: list[int] = field(default_factory=lambda: [200, 204, 301, 302, 307, 401, 403])
    rate_limit: float = 20.0
    concurrency: int = 10
    max_requests: int = 100_000
    detect_soft404: bool = True
