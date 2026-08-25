"""Tests for active crawler: storage, engine, fetcher, API, WS."""
import asyncio
import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine

from pwnproxy.services.crawler.engine import CrawlConfig, CrawlEngine
from pwnproxy.services.crawler.extractor import extract_urls, normalize_url
from pwnproxy.services.crawler.fetcher import (
    Fetcher,
    RateLimiter,
    fetch_robots,
    is_disallowed,
    parse_robots_disallow,
)
from pwnproxy.services.crawler.storage import DiscoveredURLStorage, JobORM, JobStorage
from pwnproxy.services.session.manager import ScopeConfig


# ── Helpers ──────────────────────────────────────────────────────────────


def _scope(patterns: list[str], out: list[str] | None = None) -> ScopeConfig:
    return ScopeConfig({
        "enabled": bool(patterns),
        "in_scope": patterns,
        "out_of_scope": out or [],
    })


async def _make_storage(tmpdir: str | None = None):
    if tmpdir:
        path = Path(tmpdir) / "crawler.db"
        url = f"sqlite+aiosqlite:///{path}"
    else:
        url = "sqlite+aiosqlite:///:memory:"
    engine = create_async_engine(url, echo=False)
    st = DiscoveredURLStorage(engine)
    await st.create_table()
    return engine, st


# ── 8.1 Storage: JobStorage ─────────────────────────────────────────────


class TestJobStorage:
    @pytest.mark.asyncio
    async def test_create_job(self):
        engine, _ = await _make_storage()
        try:
            js = JobStorage(engine)
            jid = await js.create(job_type="active", config={"seeds": ["https://x.com"]})
            assert jid >= 1
            job = await js.get(jid)
            assert job is not None
            assert job["type"] == "active"
            assert job["status"] == "queued"
            assert json.loads(job["config"])["seeds"] == ["https://x.com"]
        finally:
            await engine.dispose()

    @pytest.mark.asyncio
    async def test_update_status_running(self):
        engine, _ = await _make_storage()
        try:
            js = JobStorage(engine)
            jid = await js.create()
            await js.update_status(jid, "running")
            job = await js.get(jid)
            assert job["status"] == "running"
            assert job["started_at"] is not None
            assert job["finished_at"] is None
        finally:
            await engine.dispose()

    @pytest.mark.asyncio
    async def test_update_status_completed(self):
        engine, _ = await _make_storage()
        try:
            js = JobStorage(engine)
            jid = await js.create()
            await js.update_status(jid, "running")
            await js.update_status(jid, "completed")
            job = await js.get(jid)
            assert job["status"] == "completed"
            assert job["finished_at"] is not None
        finally:
            await engine.dispose()

    @pytest.mark.asyncio
    async def test_update_stats(self):
        engine, _ = await _make_storage()
        try:
            js = JobStorage(engine)
            jid = await js.create()
            await js.update_stats(jid, {"fetched": 42, "queued": 10, "discovered": 8, "errors": 0})
            job = await js.get(jid)
            stats = json.loads(job["stats"])
            assert stats["fetched"] == 42
            assert stats["discovered"] == 8
        finally:
            await engine.dispose()

    @pytest.mark.asyncio
    async def test_list_active(self):
        engine, _ = await _make_storage()
        try:
            js = JobStorage(engine)
            j1 = await js.create()
            j2 = await js.create()
            await js.update_status(j1, "running")
            await js.update_status(j2, "running")
            await js.update_status(j2, "completed")
            active = await js.list_active()
            assert len(active) == 1
            assert active[0]["id"] == j1
        finally:
            await engine.dispose()

    @pytest.mark.asyncio
    async def test_mark_stale_running_failed(self):
        engine, _ = await _make_storage()
        try:
            js = JobStorage(engine)
            j1 = await js.create()
            j2 = await js.create()
            await js.update_status(j1, "running")
            await js.update_status(j2, "queued")
            count = await js.mark_stale_running_failed()
            assert count == 1
            job1 = await js.get(j1)
            job2 = await js.get(j2)
            assert job1["status"] == "failed"
            assert job1["error"] == "worker restarted"
            assert job2["status"] == "queued"
        finally:
            await engine.dispose()


# ── 8.2 Fetcher: rate limiter, robots, verify ───────────────────────────


class TestFetcher:
    @pytest.mark.asyncio
    async def test_rate_limiter_pacing(self):
        limiter = RateLimiter(rate=5.0)
        t0 = asyncio.get_event_loop().time()
        await limiter.acquire()
        await limiter.acquire()
        elapsed = asyncio.get_event_loop().time() - t0
        assert elapsed >= 0.15  # 2 requests at 5/s = min 0.2s interval, allow small margin

    def test_parse_robots_disallow(self):
        text = "User-agent: *\nDisallow: /admin\nDisallow: /private/\nAllow: /public"
        rules = parse_robots_disallow(text)
        assert "/admin" in rules
        assert "/private/" in rules
        assert len(rules) == 2

    def test_parse_robots_empty(self):
        assert parse_robots_disallow("") == []
        assert parse_robots_disallow(None) == []  # type: ignore[arg-type]

    def test_is_disallowed(self):
        assert is_disallowed("https://target.com/admin", ["/admin"]) is True
        assert is_disallowed("https://target.com/public", ["/admin"]) is False
        assert is_disallowed("https://target.com/admin/secret", ["/admin"]) is True


# ── 8.3 Engine unit: BFS, path-only dedup, visited, depth, max_urls, scope ──


class TestCrawlEngine:
    def _scope(self) -> ScopeConfig:
        return _scope(["*://target.com/*"])

    def test_path_only_dedup(self):
        engine = CrawlEngine(
            config=CrawlConfig(seeds=["https://target.com/"], depth=2),
            scope=self._scope(),
        )
        # /page and /page?x=1 share the same path
        assert engine._path_key("https://target.com/page") == "/page"
        assert engine._path_key("https://target.com/page?x=1") == "/page"
        # First visit succeeds
        engine._visited_paths.add("/page")
        assert engine._queue_candidate("https://target.com/page?x=1", 0) is False

    def test_visited_per_job(self):
        engine1 = CrawlEngine(
            config=CrawlConfig(seeds=["https://target.com/"], depth=1),
            scope=self._scope(),
        )
        engine2 = CrawlEngine(
            config=CrawlConfig(seeds=["https://target.com/"], depth=1),
            scope=self._scope(),
        )
        engine1._visited.add("https://target.com/")
        engine1._visited_paths.add("/")
        # Engine2 has its own visited set
        assert "https://target.com/" not in engine2._visited
        assert "/" not in engine2._visited_paths

    def test_depth_cap(self):
        engine = CrawlEngine(
            config=CrawlConfig(seeds=["https://target.com/"], depth=1),
            scope=self._scope(),
        )
        # depth=0 at seed, /a is depth 1 (ok), /b from /a would be depth 2 (exceeds)
        assert engine._queue_candidate("https://target.com/a", 0) is True  # depth 1 <= 1
        assert engine._queue_candidate("https://target.com/b", 1) is False  # depth 2 > 1

    def test_scope_filter(self):
        scope = _scope(["*://target.com/*"])
        engine = CrawlEngine(
            config=CrawlConfig(seeds=["https://target.com/"], depth=3),
            scope=scope,
        )
        assert engine._queue_candidate("https://evil.com/x", 0) is False

    def test_robots_respected(self):
        engine = CrawlEngine(
            config=CrawlConfig(seeds=["https://target.com/"], depth=3, respect_robots=True),
            scope=self._scope(),
        )
        engine._disallow_paths = ["/admin"]
        assert engine._queue_candidate("https://target.com/admin", 0) is False
        assert engine._queue_candidate("https://target.com/public", 0) is True

    def test_stats(self):
        engine = CrawlEngine(
            config=CrawlConfig(seeds=["https://target.com/"], depth=1),
            scope=self._scope(),
        )
        assert engine.stats.fetched == 0
        assert engine.stats.to_dict()["fetched"] == 0


# ── 8.4 Worker E2E: crawl.start → fetches → crawl.completed ────────────


class TestWorkerCrawlE2E:
    @pytest.mark.asyncio
    async def test_crawl_start_and_complete(self):
        """Spawn worker, send crawl.start, verify crawl.completed event."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            from pwnproxy.shared.bus.transports.tcp_bridge import TcpBridgeServer, TcpBridgeClient

            feed_server = TcpBridgeServer()
            await feed_server.start()

            db_path = str(Path(tmp) / "crawler.db")
            scope_json = json.dumps({"enabled": False})
            import sys
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-m", "pwnproxy.services.crawler.crawler_worker",
                "--db-path", db_path,
                "--feed-port", str(feed_server.port),
                "--scope-json", scope_json,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            assert proc.stdout is not None
            line = await asyncio.wait_for(proc.stdout.readline(), timeout=30)
            raw = line.decode().strip()
            assert raw.startswith("EVENT_PORT=")
            event_port = int(raw.split("=")[1])

            # Connect results bridge
            results: list[dict] = []
            def _on_result(topic, data):
                results.append({"topic": topic, "data": data})
            results_bridge = TcpBridgeClient(host="127.0.0.1", port=event_port, on_event=_on_result)
            await results_bridge.start()
            await asyncio.sleep(0.3)

            # Send crawl.start with a seed pointing to a local mock
            # We'll use a simple HTTP server to serve a page with links
            from aiohttp import web

            html_content = '<html><body><a href="/page2">link</a></body></html>'
            html2 = '<html><body>leaf</body></html>'

            app_handler = web.Application()
            app_handler.router.add_get("/", lambda r: web.Response(text=html_content, content_type="text/html"))
            app_handler.router.add_get("/page2", lambda r: web.Response(text=html2, content_type="text/html"))

            runner = web.AppRunner(app_handler)
            await runner.setup()
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]

            crawl_config = {
                "seeds": [f"http://127.0.0.1:{port}/"],
                "depth": 2,
                "rate_limit": 50,
                "concurrency": 5,
                "max_urls": 10,
                "respect_robots": False,
                "include_discovered": False,
                "scan_while_crawl": False,
            }
            await feed_server.publish("crawl.start", {"job_id": 1, "config": crawl_config})

            # Wait for crawl.completed or crawl.failed (up to 30s)
            found = False
            for _ in range(600):
                for r in results:
                    if r["topic"] in ("crawl.completed", "crawl.failed"):
                        found = True
                        break
                if found:
                    break
                await asyncio.sleep(0.05)

            await runner.cleanup()

            # Verify crawler.flow events were published
            flow_events = [r for r in results if r["topic"] == "crawler.flow"]
            assert len(flow_events) >= 1, f"Expected at least 1 crawler.flow, got {len(flow_events)}"

            # Verify crawl.started was published
            assert any(r["topic"] == "crawl.started" for r in results)

            # Verify crawl.completed was published
            completed = [r for r in results if r["topic"] == "crawl.completed"]
            assert len(completed) >= 1

            # Clean up
            proc.kill()
            await proc.wait()
            await results_bridge.stop()
            await feed_server.stop()

    @pytest.mark.asyncio
    async def test_crawl_stop(self):
        """Send crawl.stop after crawl.start, verify job is stopped."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            from pwnproxy.shared.bus.transports.tcp_bridge import TcpBridgeServer, TcpBridgeClient

            feed_server = TcpBridgeServer()
            await feed_server.start()

            db_path = str(Path(tmp) / "crawler.db")
            scope_json = json.dumps({"enabled": False})
            import sys
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-m", "pwnproxy.services.crawler.crawler_worker",
                "--db-path", db_path,
                "--feed-port", str(feed_server.port),
                "--scope-json", scope_json,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            assert proc.stdout is not None
            line = await asyncio.wait_for(proc.stdout.readline(), timeout=30)
            event_port = int(line.decode().strip().split("=")[1])

            results: list[dict] = []
            def _on_result(topic, data):
                results.append({"topic": topic, "data": data})
            results_bridge = TcpBridgeClient(host="127.0.0.1", port=event_port, on_event=_on_result)
            await results_bridge.start()
            await asyncio.sleep(0.3)

            # Start a slow crawl (we'll stop it quickly)
            crawl_config = {
                "seeds": ["http://127.0.0.1:99999/"],  # will fail to connect
                "depth": 1,
                "rate_limit": 1,
                "concurrency": 1,
                "max_urls": 100,
            }
            await feed_server.publish("crawl.start", {"job_id": 2, "config": crawl_config})
            await asyncio.sleep(0.5)

            # Stop it
            await feed_server.publish("crawl.stop", {"job_id": 2})
            await asyncio.sleep(1.0)

            # Verify we got crawl.started
            assert any(r["topic"] == "crawl.started" for r in results)

            proc.kill()
            await proc.wait()
            await results_bridge.stop()
            await feed_server.stop()


# ── 8.5 API: start 200/422/409, stop, status ───────────────────────────


class TestCrawlerAPI:
    @pytest.mark.asyncio
    async def test_start_without_seeds_422(self):
        from pwnproxy.transport.rest.app import app
        client = TestClient(app, raise_server_exceptions=False)

        sm = MagicMock()
        sm.get_crawler_engine.return_value = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        app.state.session_manager = sm

        crawler_mock = MagicMock()
        crawler_mock.running = True
        app.state.crawler_process = crawler_mock

        resp = client.post("/api/v1/crawler/start", json={"seeds": []})
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_start_no_active_job(self):
        from pwnproxy.transport.rest.app import app
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        st = DiscoveredURLStorage(engine)
        await st.create_table()

        sm = MagicMock()
        sm.get_crawler_engine.return_value = engine
        app.state.session_manager = sm

        crawler_mock = MagicMock()
        crawler_mock.running = True
        crawler_mock.send_to_worker.return_value = True
        app.state.crawler_process = crawler_mock

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/crawler/start", json={"seeds": ["https://target.com"]})
        assert resp.status_code == 200
        data = resp.json()
        assert "job_id" in data
        assert data["status"] == "running"
        await engine.dispose()

    @pytest.mark.asyncio
    async def test_stop_no_active_job(self):
        from pwnproxy.transport.rest.app import app
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        st = DiscoveredURLStorage(engine)
        await st.create_table()

        sm = MagicMock()
        sm.get_crawler_engine.return_value = engine
        app.state.session_manager = sm

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/crawler/stop")
        assert resp.status_code == 200
        assert resp.json()["stopped"] is False
        await engine.dispose()

    @pytest.mark.asyncio
    async def test_status_shows_active_jobs(self):
        from pwnproxy.transport.rest.app import app
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        st = DiscoveredURLStorage(engine)
        await st.create_table()

        js = JobStorage(engine)
        jid = await js.create(job_type="active", config={"seeds": ["https://x.com"]})
        await js.update_status(jid, "running")

        sm = MagicMock()
        sm.get_crawler_engine.return_value = engine
        app.state.session_manager = sm

        crawler_mock = MagicMock()
        crawler_mock.status.return_value = {"running": True, "pid": 1234}
        app.state.crawler_process = crawler_mock

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/crawler/status")
        data = resp.json()
        assert data["running"] is True
        assert len(data["active_jobs"]) == 1
        assert data["active_jobs"][0]["id"] == jid
        await engine.dispose()


# ── 8.6 Main re-publish: crawler.flow → traffic.db ─────────────────────


class TestCrawlRepublish:
    @pytest.mark.asyncio
    async def test_crawl_flow_persisted_as_flow_record(self):
        """Verify that _store_crawl_flow persists a FlowRecord to traffic.db."""
        from pwnproxy.shared.db import FlowRecord, Base, init_db
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        await init_db(engine)
        try:
            from sqlalchemy.orm import sessionmaker
            from sqlalchemy.ext.asyncio import AsyncSession
            from pwnproxy.shared.models import Flow

            sf = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
            body = b"<html>hello</html>"
            record = FlowRecord(
                method="GET",
                url="https://target.com/crawled",
                request_headers={},
                request_body=None,
                status_code=200,
                response_headers={"content-type": "text/html"},
                response_body=body,
                duration_ms=123.4,
                tls=True,
            )
            async with sf() as session:
                session.add(record)
                await session.commit()
                db_id = record.id

            async with sf() as session:
                from sqlalchemy import select
                result = await session.execute(select(FlowRecord).where(FlowRecord.id == db_id))
                row = result.scalar_one()
                assert row.url == "https://target.com/crawled"
                assert row.method == "GET"
                assert row.status_code == 200
                assert row.tls is True
                assert row.duration_ms == 123.4
        finally:
            await engine.dispose()


# ── 8.7 WS: crawl.* events reach /ws/events ─────────────────────────────


class TestCrawlWSEvents:
    @pytest.mark.asyncio
    async def test_crawl_completed_event_dispatched(self):
        """Verify crawl.completed is dispatched via hook_bus."""
        from pwnproxy.shared.hooks import HookBus
        hb = HookBus()
        q = hb.register("crawl.completed")
        hb.publish("crawl.completed", {"job_id": 1, "fetched": 5, "discovered": 3})
        payload = await asyncio.wait_for(q.get(), timeout=1.0)
        assert payload["job_id"] == 1
        assert payload["fetched"] == 5

    @pytest.mark.asyncio
    async def test_crawl_progress_event_dispatched(self):
        from pwnproxy.shared.hooks import HookBus
        hb = HookBus()
        q = hb.register("crawl.progress")
        hb.publish("crawl.progress", {"job_id": 1, "fetched": 10, "queued": 20})
        payload = await asyncio.wait_for(q.get(), timeout=1.0)
        assert payload["fetched"] == 10

    @pytest.mark.asyncio
    async def test_crawl_failed_event_dispatched(self):
        from pwnproxy.shared.hooks import HookBus
        hb = HookBus()
        q = hb.register("crawl.failed")
        hb.publish("crawl.failed", {"job_id": 1, "error": "timeout"})
        payload = await asyncio.wait_for(q.get(), timeout=1.0)
        assert payload["error"] == "timeout"

    @pytest.mark.asyncio
    async def test_crawl_started_event_dispatched(self):
        from pwnproxy.shared.hooks import HookBus
        hb = HookBus()
        q = hb.register("crawl.started")
        hb.publish("crawl.started", {"job_id": 1})
        payload = await asyncio.wait_for(q.get(), timeout=1.0)
        assert payload["job_id"] == 1
