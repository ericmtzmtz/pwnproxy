"""Passive crawler worker subprocess.

Receives ``crawler.feed`` events (proxy flow dicts with response bodies)
from the main process over a TcpBridge, extracts URLs, filters them
against the session scope, persists new ones to ``discovered_urls``
SQLite and publishes ``crawler.url`` events back to the main process.
"""

import argparse
import asyncio
import json
import logging
import signal
import sys
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import create_async_engine

from pwnproxy.services.crawler.extractor import extract_from_headers, extract_urls
from pwnproxy.services.crawler.storage import DiscoveredURLStorage
from pwnproxy.services.session.manager import ScopeConfig
from pwnproxy.shared.bus.transports.tcp_bridge import TcpBridgeClient, TcpBridgeServer

logger = logging.getLogger("crawler_worker")

MAX_BODY_CHARS = 512 * 1024


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="pwnproxy passive crawler worker")
    parser.add_argument("--db-path", required=True, help="Path to crawler.db SQLite file")
    parser.add_argument("--feed-port", type=int, required=True, help="Port of the main-process feed bridge")
    parser.add_argument("--scope-json", default=None, help="JSON-encoded ScopeConfig")
    return parser.parse_args()


class CrawlerWorker:
    def __init__(self, args: argparse.Namespace):
        self._db_path = args.db_path
        self._bridge = TcpBridgeServer()
        self._storage: DiscoveredURLStorage | None = None
        scope_data = json.loads(args.scope_json) if args.scope_json else None
        self._scope = ScopeConfig(scope_data)
        self._feed_client = TcpBridgeClient(
            host="127.0.0.1",
            port=args.feed_port,
            on_event=self._on_feed_event,
        )
        self._running = False

    async def start(self) -> None:
        engine = create_async_engine(f"sqlite+aiosqlite:///{self._db_path}", echo=False)
        self._storage = DiscoveredURLStorage(engine)
        await self._storage.create_table()

        await self._bridge.start()
        print(f"EVENT_PORT={self._bridge.port}", flush=True)

        await self._feed_client.start()
        self._running = True
        logger.info("Crawler worker started (scope in=%d out=%d enabled=%s)",
                    len(self._scope.in_scope), len(self._scope.out_of_scope), self._scope.enabled)

    async def stop(self) -> None:
        self._running = False
        await self._feed_client.stop()
        await self._bridge.stop()

    def _content_type(self, headers: dict) -> str:
        for name, value in (headers or {}).items():
            if (name or "").lower() == "content-type":
                return value or ""
        return ""

    def _on_feed_event(self, topic: str, data: dict) -> None:
        if topic != "crawler.feed" or not isinstance(data, dict):
            return
        if not self._running:
            return
        asyncio.create_task(self._process(data))

    async def _process(self, data: dict) -> None:
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
