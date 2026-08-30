"""Active crawl strategy: BFS from seeds using CrawlEngine.

Moved from ``CrawlerWorker._run_crawl`` without rewriting logic.
The function signature takes explicit dependencies (no ``self``) so it
is independently testable.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from pwnproxy.services.crawler.engine import CrawlConfig, CrawlEngine
from pwnproxy.services.crawler.fetcher import Fetcher as _DefaultFetcher
from pwnproxy.services.crawler.strategies.passive import extract_and_persist
from pwnproxy.shared.observability import gen_correlation_id, set_correlation_id

if TYPE_CHECKING:
    from pwnproxy.services.crawler.events import EventPublisher
    from pwnproxy.services.crawler.storage import DiscoveredURLStorage
    from pwnproxy.services.crawler.lifecycle import CrawlStartConfig
    from pwnproxy.services.jobs.lifecycle import JobLifecycle
    from pwnproxy.services.session.manager import ScopeConfig

logger = logging.getLogger(__name__)


async def run_crawl(
    job_id: int | None,
    config: "CrawlStartConfig",
    *,
    scope: "ScopeConfig",
    ssl_insecure: bool,
    storage: "DiscoveredURLStorage | None",
    lifecycle: "JobLifecycle | None",
    events: "EventPublisher",
    state: dict,
    fetcher_cls=None,
) -> None:
    """Execute an active BFS crawl from seeds.

    ``state`` is the shared mutable coordinator state dict (``active_task``,
    ``active_job_id``, ``stop_requested``).
    """
    set_correlation_id(gen_correlation_id())
    engine: CrawlEngine | None = None
    try:
        # Build CrawlConfig from the lifecycle config.
        crawl_config = CrawlConfig(
            seeds=list(config.seeds),
            depth=config.depth,
            rate_limit=config.rate_limit,
            concurrency=config.concurrency,
            max_urls=config.max_urls,
            respect_robots=config.respect_robots,
            include_discovered=config.include_discovered,
            scan_while_crawl=config.scan_while_crawl,
        )

        # If include_discovered, add existing discovered URLs as seeds.
        if crawl_config.include_discovered and storage:
            existing = await storage.list(limit=200)
            for row in existing:
                url = row.get("url", "")
                if url and url not in crawl_config.seeds:
                    crawl_config.seeds.append(url)

        engine = CrawlEngine(
            config=crawl_config,
            scope=scope,
            verify=not ssl_insecure,
        )
        fetcher = (fetcher_cls or _DefaultFetcher)(rate_limit=config.rate_limit, verify=not ssl_insecure)
        await fetcher.start()
        try:
            last_progress = datetime.now(timezone.utc)
            async for flow_dict in engine.run(fetcher):
                flow_dict["_scan_while_crawl"] = config.scan_while_crawl
                await events.crawl_flow(flow_dict)

                # Persist to discovered_urls and publish crawler.url.
                if storage:
                    await extract_and_persist(flow_dict, scope, storage, events)

                # Emit progress every ~1s or 10 fetches.
                now = datetime.now(timezone.utc)
                elapsed = (now - last_progress).total_seconds()
                if elapsed >= 1.0 or engine.stats.fetched % 10 == 0:
                    await events.crawl_progress(job_id, engine.stats.to_dict())
                    last_progress = now

            # Final progress.
            await events.crawl_progress(job_id, engine.stats.to_dict())
        finally:
            await fetcher.stop()

        # Mark completed.
        if lifecycle and job_id:
            await lifecycle.update_stats(job_id, engine.stats.to_dict())
            await lifecycle.complete(job_id)
        await events.crawl_completed(job_id, engine.stats.to_dict())

    except asyncio.CancelledError:
        if lifecycle and job_id:
            await lifecycle.safe_cancel(job_id)
        if not state["stop_requested"]:
            await events.crawl_failed(job_id, "cancelled")

    except Exception as exc:
        logger.exception("Crawl job %s failed", job_id)
        stats = (
            engine.stats.to_dict()
            if engine is not None
            else {"fetched": 0, "queued": 0, "discovered": 0, "errors": 0, "maxed": False}
        )
        stats["errors"] = stats.get("errors", 0) + 1
        if lifecycle and job_id:
            await lifecycle.update_stats(job_id, stats)
            await lifecycle.safe_fail(job_id, str(exc))
        await events.crawl_failed(job_id, str(exc))

    finally:
        state["active_task"] = None
        state["active_job_id"] = None
        state["stop_requested"] = False
