"""Crawler worker subprocess.

Handles two roles:
1. **Passive**: receives ``crawler.feed`` events (proxy flow dicts) over a
   TcpBridge, extracts URLs, persists new ones to ``discovered_urls``.
2. **Active**: on ``crawl.start`` messages, runs a BFS crawl from seeds
   using the ``CrawlEngine``, publishing ``crawler.flow`` and ``crawl.*``
   events back to the main process.
"""

import argparse
import asyncio
import json
import logging
import signal
import sys
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import create_async_engine

from pwnproxy.services.crawler.engine import CrawlConfig, CrawlEngine
from pwnproxy.services.crawler.extractor import extract_from_headers, extract_urls
from pwnproxy.services.crawler.fetcher import Fetcher
from pwnproxy.services.crawler.storage import DiscoveredURLStorage, JobStorage
from pwnproxy.services.session.manager import ScopeConfig
from pwnproxy.shared.bus.transports.tcp_bridge import TcpBridgeClient, TcpBridgeServer

logger = logging.getLogger("crawler_worker")

MAX_BODY_CHARS = 512 * 1024


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="pwnproxy crawler worker")
    parser.add_argument("--db-path", required=True, help="Path to crawler.db SQLite file")
    parser.add_argument("--feed-port", type=int, required=True, help="Port of the main-process feed bridge")
    parser.add_argument("--scope-json", default=None, help="JSON-encoded ScopeConfig")
    parser.add_argument("--ssl-insecure", action="store_true", default=True,
                        help="Disable TLS verification for active fetches (default True)")
    return parser.parse_args()


class CrawlerWorker:
    def __init__(self, args: argparse.Namespace):
        self._db_path = args.db_path
        self._ssl_insecure = args.ssl_insecure
        self._bridge = TcpBridgeServer()
        self._storage: DiscoveredURLStorage | None = None
        self._job_storage: JobStorage | None = None
        scope_data = json.loads(args.scope_json) if args.scope_json else None
        self._scope = ScopeConfig(scope_data)
        self._feed_client = TcpBridgeClient(
            host="127.0.0.1",
            port=args.feed_port,
            on_event=self._on_feed_event,
        )
        self._running = False
        self._active_task: asyncio.Task | None = None
        self._active_job_id: int | None = None

    async def start(self) -> None:
        engine = create_async_engine(f"sqlite+aiosqlite:///{self._db_path}", echo=False)
        self._storage = DiscoveredURLStorage(engine)
        await self._storage.create_table()
        self._job_storage = JobStorage(engine)

        # Crash recovery: mark stale running jobs as failed.
        stale = await self._job_storage.mark_stale_running_failed()
        if stale:
            logger.info("Crash recovery: marked %d stale running job(s) as failed", stale)

        await self._bridge.start()
        print(f"EVENT_PORT={self._bridge.port}", flush=True)

        await self._feed_client.start()
        self._running = True
        logger.info("Crawler worker started (scope in=%d out=%d enabled=%s)",
                    len(self._scope.in_scope), len(self._scope.out_of_scope), self._scope.enabled)

    async def stop(self) -> None:
        self._running = False
        if self._active_task and not self._active_task.done():
            self._active_task.cancel()
            try:
                await self._active_task
            except (asyncio.CancelledError, Exception):
                pass
            self._active_task = None
        await self._feed_client.stop()
        await self._bridge.stop()

    def _content_type(self, headers: dict) -> str:
        for name, value in (headers or {}).items():
            if (name or "").lower() == "content-type":
                return value or ""
        return ""

    # ── Feed event dispatcher ────────────────────────────────────────

    def _on_feed_event(self, topic: str, data: dict) -> None:
        if topic == "crawl.start" and isinstance(data, dict):
            asyncio.create_task(self._handle_crawl_start(data))
            return
        if topic == "crawl.stop" and isinstance(data, dict):
            self._handle_crawl_stop(data)
            return
        if topic != "crawler.feed" or not isinstance(data, dict):
            return
        if not self._running:
            return
        asyncio.create_task(self._process_passive(data))

    # ── Active crawl ─────────────────────────────────────────────────

    async def _handle_crawl_start(self, msg: dict) -> None:
        if self._active_task and not self._active_task.done():
            logger.warning("crawl.start ignored: a job is already running")
            return
        job_id = msg.get("job_id")
        config_raw = msg.get("config", {})
        if isinstance(config_raw, str):
            config_raw = json.loads(config_raw)
        config = CrawlConfig(
            seeds=config_raw.get("seeds", []),
            depth=config_raw.get("depth", 3),
            rate_limit=config_raw.get("rate_limit", 10.0),
            concurrency=config_raw.get("concurrency", 5),
            max_urls=config_raw.get("max_urls", 1000),
            respect_robots=config_raw.get("respect_robots", False),
            include_discovered=config_raw.get("include_discovered", False),
            scan_while_crawl=config_raw.get("scan_while_crawl", False),
        )
        self._active_job_id = job_id
        await self._bridge.publish("crawl.started", {"job_id": job_id})
        if self._job_storage and job_id:
            await self._job_storage.update_status(job_id, "running")
        self._active_task = asyncio.create_task(self._run_crawl(job_id, config))

    def _handle_crawl_stop(self, msg: dict) -> None:
        job_id = msg.get("job_id")
        if self._active_task and not self._active_task.done():
            logger.info("Stopping crawl job %s", job_id)
            self._active_task.cancel()
        if self._job_storage and job_id:
            asyncio.create_task(self._job_storage.update_status(job_id, "stopped"))
        self._active_task = None

    async def _run_crawl(self, job_id: int | None, config: CrawlConfig) -> None:
        try:
            # If include_discovered, add existing discovered URLs as seeds.
            if config.include_discovered and self._storage:
                existing = await self._storage.list(limit=200)
                for row in existing:
                    url = row.get("url", "")
                    if url and url not in config.seeds:
                        config.seeds.append(url)

            engine = CrawlEngine(
                config=config,
                scope=self._scope,
                verify=self._ssl_insecure,
            )
            fetcher = Fetcher(rate_limit=config.rate_limit, verify=self._ssl_insecure)
            await fetcher.start()
            try:
                last_progress = datetime.now(timezone.utc)
                async for flow_dict in engine.run(fetcher):
                    # Attach scan_while_crawl so the main can decide about done events.
                    flow_dict["_scan_while_crawl"] = config.scan_while_crawl
                    # Publish the flow to the main process for traffic.db persistence.
                    await self._bridge.publish("crawler.flow", flow_dict)

                    # Persist to discovered_urls and publish crawler.url.
                    await self._publish_discovered(flow_dict)

                    # Emit progress every ~1s or 10 fetches.
                    now = datetime.now(timezone.utc)
                    elapsed = (now - last_progress).total_seconds()
                    if elapsed >= 1.0 or engine.stats.fetched % 10 == 0:
                        await self._bridge.publish("crawl.progress", {
                            "job_id": job_id,
                            **engine.stats.to_dict(),
                        })
                        last_progress = now

                # Final progress.
                await self._bridge.publish("crawl.progress", {
                    "job_id": job_id,
                    **engine.stats.to_dict(),
                })
            finally:
                await fetcher.stop()

            # Mark completed.
            if self._job_storage and job_id:
                await self._job_storage.update_stats(job_id, engine.stats.to_dict())
                await self._job_storage.update_status(job_id, "completed")
            await self._bridge.publish("crawl.completed", {
                "job_id": job_id,
                **engine.stats.to_dict(),
            })
        except asyncio.CancelledError:
            if self._job_storage and job_id:
                await self._job_storage.update_status(job_id, "stopped")
            await self._bridge.publish("crawl.failed", {
                "job_id": job_id,
                "error": "cancelled",
            })
        except Exception as exc:
            logger.exception("Crawl job %s failed", job_id)
            if self._job_storage and job_id:
                await self._job_storage.update_stats(job_id, {
                    "fetched": getattr(exc, "_stats_fetched", 0),
                    "queued": 0,
                    "discovered": 0,
                    "errors": 1,
                })
                await self._job_storage.update_status(job_id, "failed", error=str(exc))
            await self._bridge.publish("crawl.failed", {
                "job_id": job_id,
                "error": str(exc),
            })
        finally:
            self._active_task = None
            self._active_job_id = None

    async def _publish_discovered(self, flow_dict: dict) -> None:
        """From a crawled response, extract and persist URLs to discovered_urls."""
        base_url = flow_dict.get("url") or ""
        method = flow_dict.get("method") or "GET"
        if not base_url or not self._scope.is_in_scope(base_url):
            return
        headers = flow_dict.get("response_headers") or {}
        body = flow_dict.get("response_body")
        candidates: list[tuple[str, str]] = []
        if body:
            body_str = body[:MAX_BODY_CHARS] if isinstance(body, str) else body
            candidates.extend(extract_urls(body_str, base_url, content_type=self._content_type(headers)))
        candidates.extend(extract_from_headers(headers, base_url))

        seen: set[str] = set()
        for url, source in candidates:
            if url in seen:
                continue
            seen.add(url)
            if not self._scope.is_in_scope(url):
                continue
            assert self._storage is not None
            new_id = await self._storage.save(url=url, source=source, method=method, base_url=base_url)
            if new_id is None:
                continue
            await self._bridge.publish("crawler.url", {
                "id": new_id,
                "url": url,
                "source": source,
                "method": method,
                "base_url": base_url,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    # ── Passive crawl ────────────────────────────────────────────────

    async def _process_passive(self, data: dict) -> None:
        try:
            base_url = data.get("url") or ""
            method = data.get("method") or "GET"
            if not base_url or not self._scope.is_in_scope(base_url):
                return
            headers = data.get("response_headers") or {}
            body = data.get("response_body")
            candidates: list[tuple[str, str]] = []
            if body:
                body = body[:MAX_BODY_CHARS]
                candidates.extend(extract_urls(body, base_url, content_type=self._content_type(headers)))
            candidates.extend(extract_from_headers(headers, base_url))

            seen: set[str] = set()
            for url, source in candidates:
                if url in seen:
                    continue
                seen.add(url)
                if not self._scope.is_in_scope(url):
                    continue
                assert self._storage is not None
                new_id = await self._storage.save(url=url, source=source, method=method, base_url=base_url)
                if new_id is None:
                    continue
                await self._bridge.publish("crawler.url", {
                    "id": new_id,
                    "url": url,
                    "source": source,
                    "method": method,
                    "base_url": base_url,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
        except Exception:
            logger.exception("crawler feed processing failed")


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
