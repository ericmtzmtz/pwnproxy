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
import dataclasses
import json
import logging
import signal
import sys
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import create_async_engine

from pwnproxy.services.crawler.engine import CrawlConfig, CrawlEngine
from pwnproxy.services.crawler.extractor import extract_from_headers, extract_urls
from pwnproxy.services.crawler.fetcher import Fetcher, learn_baseline
from pwnproxy.services.crawler.storage import DiscoveredURLStorage, JobStorage
from pwnproxy.services.session.manager import ScopeConfig
from pwnproxy.shared.bus.transports.tcp_bridge import TcpBridgeClient, TcpBridgeServer

logger = logging.getLogger("crawler_worker")

@dataclasses.dataclass
class BruteforceConfig:
    base_urls: list[str]
    wordlist: list[str]  # already resolved to list by API
    extensions: list[str] = dataclasses.field(default_factory=list)
    status_filter: list[int] = dataclasses.field(default_factory=lambda: [200, 204, 301, 302, 307, 401, 403])
    rate_limit: float = 20.0
    concurrency: int = 10
    max_requests: int = 100_000
    detect_soft404: bool = True

MAX_BODY_CHARS = 512 * 1024


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
        self._stop_requested = False

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
        # Bruteforce handlers
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
            self._stop_requested = True
            self._active_task.cancel()
        if self._job_storage and job_id:
            asyncio.create_task(self._job_storage.update_status(job_id, "stopped"))
        self._active_task = None

    async def _handle_bruteforce_start(self, msg: dict) -> None:
        if self._active_task and not self._active_task.done():
            logger.warning("bruteforce.start ignored: a job is already running")
            return
        job_id = msg.get("job_id")
        config_raw = msg.get("config", {})
        if isinstance(config_raw, str):
            config_raw = json.loads(config_raw)
        config = BruteforceConfig(
            base_urls=config_raw.get("base_urls", []),
            wordlist=config_raw.get("wordlist", []),
            extensions=config_raw.get("extensions", []),
            status_filter=config_raw.get("status_filter", []),
            rate_limit=config_raw.get("rate_limit", 20.0),
            concurrency=config_raw.get("concurrency", 10),
            max_requests=config_raw.get("max_requests", 100_000),
            detect_soft404=config_raw.get("detect_soft404", True),
        )
        self._active_job_id = job_id
        await self._bridge.publish("bruteforce.started", {"job_id": job_id})
        if self._job_storage and job_id:
            await self._job_storage.update_status(job_id, "running")
        self._active_task = asyncio.create_task(self._run_bruteforce(job_id, config))

    def _handle_bruteforce_stop(self, msg: dict) -> None:
        job_id = msg.get("job_id")
        if self._active_task and not self._active_task.done():
            logger.info("Stopping bruteforce job %s", job_id)
            self._stop_requested = True
            self._active_task.cancel()
        if self._job_storage and job_id:
            asyncio.create_task(self._job_storage.update_status(job_id, "stopped"))
        self._active_task = None

    async def _run_crawl(self, job_id: int | None, config: CrawlConfig) -> None:
        engine: CrawlEngine | None = None
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
                verify=not self._ssl_insecure,
            )
            fetcher = Fetcher(rate_limit=config.rate_limit, verify=not self._ssl_insecure)
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
            if not self._stop_requested:
                await self._bridge.publish("crawl.failed", {
                    "job_id": job_id,
                    "error": "cancelled",
                })
        except Exception as exc:
            logger.exception("Crawl job %s failed", job_id)
            stats = (
                engine.stats.to_dict()
                if engine is not None
                else {"fetched": 0, "queued": 0, "discovered": 0, "errors": 0, "maxed": False}
            )
            stats["errors"] = stats.get("errors", 0) + 1
            if self._job_storage and job_id:
                await self._job_storage.update_stats(job_id, stats)
                await self._job_storage.update_status(job_id, "failed", error=str(exc))
            await self._bridge.publish("crawl.failed", {
                "job_id": job_id,
                "error": str(exc),
            })
        finally:
            self._active_task = None
            self._active_job_id = None
            self._stop_requested = False

    async def _run_bruteforce(self, job_id: int | None, config: BruteforceConfig) -> None:
        try:
            if self._storage is None:
                raise RuntimeError("DiscoveredURLStorage not initialized")
            fetcher = Fetcher(rate_limit=config.rate_limit, verify=not self._ssl_insecure)
            await fetcher.start()
            try:
                # Build URL queue: for each base_url × word × (1 + extensions).
                urls: list[tuple[str, str]] = []  # (url, base)
                for base in config.base_urls:
                    base_clean = base.rstrip('/')
                    for word in config.wordlist:
                        urls.append((f"{base_clean}/{word}", base_clean))
                        for ext in config.extensions:
                            urls.append((f"{base_clean}/{word}{ext}", base_clean))

                # max_requests backstop: hard cap on probes actually sent.
                maxed = len(urls) > config.max_requests
                if maxed:
                    urls = urls[:config.max_requests]
                total_planned = len(urls)

                # Baseline anti soft-404, learned per base URL (signatures differ per server).
                baselines: dict[str, set[tuple[int, int]]] = {}
                if config.detect_soft404:
                    for base in dict.fromkeys(b.rstrip('/') for b in config.base_urls):
                        baselines[base] = await learn_baseline(fetcher, base)

                # Probing loop with concurrency semaphore.
                sem = asyncio.Semaphore(config.concurrency)
                probed = 0
                found = 0
                errors = 0
                skipped = 0
                soft404_filtered = 0
                last_progress = datetime.now(timezone.utc)

                async def _probe_one(url: str) -> tuple[str, tuple[int, int, str] | None, str]:
                    async with sem:
                        if self._stop_requested:
                            return url, None, "stopped"
                        if not self._scope.is_in_scope(url):
                            return url, None, "out_of_scope"
                        try:
                            result = await fetcher.probe(url)
                        except Exception:
                            return url, None, "error"
                        return url, result, "ok"

                batch_size = 50
                stopped_cooperatively = False
                for i in range(0, len(urls), batch_size):
                    if self._stop_requested:
                        stopped_cooperatively = True
                        break
                    batch = urls[i:i + batch_size]
                    tasks = [asyncio.create_task(_probe_one(u)) for u, _b in batch]
                    results = await asyncio.gather(*tasks)

                    for (url, base), (_u, probe_result, reason) in zip(batch, results):
                        if reason == "stopped":
                            stopped_cooperatively = True
                            skipped += 1
                            continue
                        if reason == "out_of_scope":
                            skipped += 1
                            continue
                        if probe_result is None or reason == "error":
                            errors += 1
                            continue

                        probed += 1
                        status_code, content_length, _ctype = probe_result

                        # Status filter.
                        if status_code not in config.status_filter:
                            continue

                        # Soft-404 baseline filter (per-base signatures).
                        if config.detect_soft404 and (status_code, content_length) in baselines.get(base, set()):
                            soft404_filtered += 1
                            continue

                        # Hit! Persist to discovered_urls and publish crawler.url.
                        found += 1
                        new_id = await self._storage.save(
                            url=url, source="bruteforce", method="GET",
                            base_url=base + '/',
                        )
                        if new_id is not None:
                            await self._bridge.publish("crawler.url", {
                                "id": new_id,
                                "url": url,
                                "source": "bruteforce",
                                "method": "GET",
                                "base_url": base + '/',
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            })

                    now = datetime.now(timezone.utc)
                    if (now - last_progress).total_seconds() >= 1.0:
                        await self._bridge.publish("bruteforce.progress", {
                            "job_id": job_id,
                            "probed": probed, "found": found, "errors": errors,
                            "skipped": skipped, "soft404_filtered": soft404_filtered,
                            "total_planned": total_planned, "maxed": maxed,
                        })
                        last_progress = now

                # Cooperative stop: stop handler already marks the job stopped;
                # do NOT publish completed for a job the user asked to stop.
                if stopped_cooperatively:
                    return

                # Final stats.
                stats = {
                    "probed": probed, "found": found, "errors": errors,
                    "skipped": skipped, "soft404_filtered": soft404_filtered,
                    "total_planned": total_planned, "maxed": maxed,
                }
                await self._bridge.publish("bruteforce.progress", {"job_id": job_id, **stats})

                if self._job_storage and job_id:
                    await self._job_storage.update_stats(job_id, stats)
                    await self._job_storage.update_status(job_id, "completed")
                await self._bridge.publish("bruteforce.completed", {"job_id": job_id, **stats})

            finally:
                await fetcher.stop()

        except asyncio.CancelledError:
            if self._job_storage and job_id:
                await self._job_storage.update_status(job_id, "stopped")
            if not self._stop_requested:
                await self._bridge.publish("bruteforce.failed", {
                    "job_id": job_id, "error": "cancelled",
                })
        except Exception as exc:
            logger.exception("Bruteforce job %s failed", job_id)
            if self._job_storage and job_id:
                await self._job_storage.update_status(job_id, "failed", error=str(exc))
            await self._bridge.publish("bruteforce.failed", {
                "job_id": job_id, "error": str(exc),
            })
        finally:
            self._active_task = None
            self._active_job_id = None
            self._stop_requested = False

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
