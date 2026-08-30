"""Crawler worker subprocess — slim coordinator.

Handles two roles:
1. **Passive**: receives ``crawler.feed`` events (proxy flow dicts) over a
   TcpBridge, extracts URLs, persists new ones to ``discovered_urls``.
2. **Active**: on ``crawl.start`` messages, runs a BFS crawl from seeds
   using the ``CrawlEngine``, publishing ``crawler.flow`` and ``crawl.*``
   events back to the main process.

The actual strategy logic lives in ``strategies/{passive,active,directory}.py``,
job lifecycle sequences in ``lifecycle.py``, and event publishing in ``events.py``.
This module wires them together and owns the process lifecycle (start/stop/signal).
"""

import argparse
import asyncio
import json
import logging
import signal
import sys

from sqlalchemy.ext.asyncio import create_async_engine

from pwnproxy.services.crawler.events import EventPublisher
from pwnproxy.services.crawler.fetcher import Fetcher  # noqa: F401 — re-exported for test monkeypatching
from pwnproxy.services.crawler.lifecycle import (
    BruteforceStartConfig,
    CrawlStartConfig,
)
from pwnproxy.services.crawler.storage import DiscoveredURLStorage, JobStorage
from pwnproxy.services.crawler.strategies.active import run_crawl
from pwnproxy.services.crawler.strategies.directory import run_bruteforce
from pwnproxy.services.crawler.strategies.passive import extract_and_persist, process_passive
from pwnproxy.services.jobs.lifecycle import JobLifecycle
from pwnproxy.services.session.manager import ScopeConfig
from pwnproxy.shared.bus.transports.tcp_bridge import TcpBridgeClient, TcpBridgeServer

# Backward-compatible re-exports for tests that import from this module.
BruteforceConfig = BruteforceStartConfig
CrawlConfig = CrawlStartConfig

logger = logging.getLogger("crawler_worker")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="pwnproxy crawler worker")
    parser.add_argument("--db-path", required=True, help="Path to crawler.db SQLite file")
    parser.add_argument("--feed-port", type=int, required=True, help="Port of the main-process feed bridge")
    parser.add_argument("--scope-json", default=None, help="JSON-encoded ScopeConfig")
    parser.add_argument("--ssl-insecure", action="store_true", default=False,
                        help="Disable TLS verification for active fetches")
    return parser.parse_args()


class CrawlerWorker:
    def __init__(self, args: argparse.Namespace):
        self._db_path = args.db_path
        self._ssl_insecure = args.ssl_insecure
        self._bridge = TcpBridgeServer()
        self._storage: DiscoveredURLStorage | None = None
        self._job_storage: JobStorage | None = None
        self._lifecycle_obj: JobLifecycle | None = None
        scope_data = json.loads(args.scope_json) if args.scope_json else None
        self._scope = ScopeConfig(scope_data)
        self._feed_client = TcpBridgeClient(
            host="127.0.0.1",
            port=args.feed_port,
            on_event=self._on_feed_event,
        )
        self._running = False
        # Shared mutable state for the coordinator and strategies.
        self._state: dict = {
            "active_task": None,
            "active_job_id": None,
            "stop_requested": False,
        }
        self._events: EventPublisher | None = None

    @property
    def _lifecycle(self) -> JobLifecycle | None:
        if getattr(self, "_lifecycle_obj", None) is None and self._job_storage is not None:
            self._lifecycle_obj = JobLifecycle(self._job_storage)
        return getattr(self, "_lifecycle_obj", None)

    async def start(self) -> None:
        engine = create_async_engine(f"sqlite+aiosqlite:///{self._db_path}", echo=False)
        self._storage = DiscoveredURLStorage(engine)
        await self._storage.create_table()
        self._job_storage = JobStorage(engine)

        # Crash recovery: mark stale running jobs as failed.
        stale = await self._lifecycle.recover_stale()
        if stale:
            logger.info("Crash recovery: marked %d stale running job(s) as failed", stale)

        await self._bridge.start()
        self._events = EventPublisher(self._bridge)
        print(f"EVENT_PORT={self._bridge.port}", flush=True)

        await self._feed_client.start()
        self._running = True
        logger.info("Crawler worker started (scope in=%d out=%d enabled=%s)",
                    len(self._scope.in_scope), len(self._scope.out_of_scope), self._scope.enabled)

    async def stop(self) -> None:
        self._running = False
        task = self._state["active_task"]
        if task and not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
            self._state["active_task"] = None
        await self._feed_client.stop()
        await self._bridge.stop()

    # ── Feed event dispatcher ────────────────────────────────────────

    def _on_feed_event(self, topic: str, data: dict) -> None:
        if topic == "scope.updated" and isinstance(data, dict):
            new_scope = ScopeConfig(data)
            if self._scope is not None:
                self._scope.in_scope = new_scope.in_scope
                self._scope.out_of_scope = new_scope.out_of_scope
                self._scope.enabled = new_scope.enabled
            else:
                self._scope = new_scope
            logger.info("Scope updated live: in=%d out=%d enabled=%s",
                        len(self._scope.in_scope), len(self._scope.out_of_scope), self._scope.enabled)
            return
        if topic == "crawl.start" and isinstance(data, dict):
            asyncio.create_task(self._handle_crawl_start(data))
            return
        if topic == "crawl.stop" and isinstance(data, dict):
            self._handle_crawl_stop(data)
            return
        if topic == "bruteforce.start" and isinstance(data, dict):
            asyncio.create_task(self._handle_bruteforce_start(data))
            return
        if topic == "bruteforce.stop" and isinstance(data, dict):
            self._handle_bruteforce_stop(data)
            return
        if topic != "crawler.feed" or not isinstance(data, dict):
            return
        if not self._running:
            return
        asyncio.create_task(self._run_passive(data))

    async def _run_passive(self, data: dict) -> None:
        if self._storage and self._events:
            await process_passive(data, self._scope, self._storage, self._events)

    # ── Active crawl ─────────────────────────────────────────────────

    async def _handle_crawl_start(self, msg: dict) -> None:
        if self._state["active_task"] and not self._state["active_task"].done():
            logger.warning("crawl.start ignored: a job is already running")
            return
        job_id = msg.get("job_id")
        config_raw = msg.get("config", {})
        if isinstance(config_raw, str):
            config_raw = json.loads(config_raw)
        config = CrawlStartConfig(
            seeds=config_raw.get("seeds", []),
            depth=config_raw.get("depth", 3),
            rate_limit=config_raw.get("rate_limit", 10.0),
            concurrency=config_raw.get("concurrency", 5),
            max_urls=config_raw.get("max_urls", 1000),
            respect_robots=config_raw.get("respect_robots", False),
            include_discovered=config_raw.get("include_discovered", False),
            scan_while_crawl=config_raw.get("scan_while_crawl", False),
        )
        self._state["active_job_id"] = job_id
        if self._events:
            await self._events.crawl_started(job_id)
        if self._lifecycle and job_id:
            await self._lifecycle.start(job_id)
        self._state["active_task"] = asyncio.create_task(
            self._run_crawl(job_id, config)
        )

    def _handle_crawl_stop(self, msg: dict) -> None:
        job_id = msg.get("job_id")
        task = self._state["active_task"]
        if task and not task.done():
            logger.info("Stopping crawl job %s", job_id)
            self._state["stop_requested"] = True
            task.cancel()
        if self._lifecycle and job_id:
            asyncio.create_task(self._lifecycle.safe_request_stop(job_id))
        self._state["active_task"] = None

    # ── Bruteforce ───────────────────────────────────────────────────

    async def _handle_bruteforce_start(self, msg: dict) -> None:
        if self._state["active_task"] and not self._state["active_task"].done():
            logger.warning("bruteforce.start ignored: a job is already running")
            return
        job_id = msg.get("job_id")
        config_raw = msg.get("config", {})
        if isinstance(config_raw, str):
            config_raw = json.loads(config_raw)
        config = BruteforceStartConfig(
            base_urls=config_raw.get("base_urls", []),
            wordlist=config_raw.get("wordlist", []),
            extensions=config_raw.get("extensions", []),
            status_filter=config_raw.get("status_filter", []),
            rate_limit=config_raw.get("rate_limit", 20.0),
            concurrency=config_raw.get("concurrency", 10),
            max_requests=config_raw.get("max_requests", 100_000),
            detect_soft404=config_raw.get("detect_soft404", True),
        )
        self._state["active_job_id"] = job_id
        if self._events:
            await self._events.bruteforce_started(job_id)
        if self._lifecycle and job_id:
            await self._lifecycle.start(job_id)
        self._state["active_task"] = asyncio.create_task(
            self._run_bruteforce(job_id, config)
        )

    def _handle_bruteforce_stop(self, msg: dict) -> None:
        job_id = msg.get("job_id")
        task = self._state["active_task"]
        if task and not task.done():
            logger.info("Stopping bruteforce job %s", job_id)
            self._state["stop_requested"] = True
            task.cancel()
        if self._lifecycle and job_id:
            asyncio.create_task(self._lifecycle.safe_request_stop(job_id))
        self._state["active_task"] = None

    # ── Strategy delegates (thin wrappers for backward-compat) ───────

    async def _run_crawl(self, job_id, config):
        """Delegate to strategy; accepts CrawlConfig or CrawlStartConfig."""
        if isinstance(config, CrawlStartConfig):
            start_config = config
        else:
            # Engine's CrawlConfig — adapt to CrawlStartConfig
            start_config = CrawlStartConfig(
                seeds=list(config.seeds),
                depth=config.depth,
                rate_limit=config.rate_limit,
                concurrency=config.concurrency,
                max_urls=config.max_urls,
                respect_robots=config.respect_robots,
                include_discovered=config.include_discovered,
                scan_while_crawl=getattr(config, "scan_while_crawl", False),
            )
        await run_crawl(
            job_id, start_config,
            scope=self._scope,
            ssl_insecure=self._ssl_insecure,
            storage=self._storage,
            lifecycle=self._lifecycle,
            events=self._events,
            state=self._state,
            fetcher_cls=Fetcher,
        )

    async def _run_bruteforce(self, job_id, config):
        """Delegate to strategy."""
        await run_bruteforce(
            job_id, config,
            scope=self._scope,
            ssl_insecure=self._ssl_insecure,
            storage=self._storage,
            lifecycle=self._lifecycle,
            events=self._events,
            state=self._state,
            fetcher_cls=Fetcher,
        )

    async def _publish_discovered(self, flow_dict):
        """Delegate to passive strategy."""
        if self._storage and self._events:
            await extract_and_persist(flow_dict, self._scope, self._storage, self._events)

    async def _process_passive(self, data):
        """Delegate to passive strategy."""
        await self._run_passive(data)


async def main() -> None:
    args = _parse_args()
    logging.basicConfig(level=logging.INFO)

    worker = CrawlerWorker(args)

    def _shutdown():
        asyncio.create_task(worker.stop())

    if sys.platform != "win32":
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGTERM, _shutdown)
        loop.add_signal_handler(signal.SIGINT, _shutdown)
    else:
        signal.signal(signal.SIGTERM, lambda s, f: _shutdown())
        signal.signal(signal.SIGINT, lambda s, f: _shutdown())

    await worker.start()
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
