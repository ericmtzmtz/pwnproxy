"""Tests for active crawler: storage, engine, fetcher, API, WS."""
import asyncio
import ipaddress
import json
import ssl
import tempfile
from datetime import datetime, timedelta, timezone
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
        # Both engines mark their own seeds as visited (fresh job can re-crawl
        # what a previous job visited).
        assert "https://target.com/" in engine1._visited
        assert "https://target.com/" in engine2._visited
        # But visited state is per-job: engine1's discoveries don't leak.
        engine1._visited.add("https://target.com/page")
        engine1._visited_paths.add("/page")
        assert "https://target.com/page" not in engine2._visited
        assert "/page" not in engine2._visited_paths

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

            # Verify BFS recursion: the seed AND the linked page were both fetched.
            flow_urls = {r["data"]["url"] for r in flow_events}
            assert f"http://127.0.0.1:{port}/" in flow_urls, f"seed not fetched, got {flow_urls}"
            assert f"http://127.0.0.1:{port}/page2" in flow_urls, f"linked page not fetched, got {flow_urls}"

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

            # Mimic the API: the main process creates the job row.
            pre_engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}", echo=False)
            st_pre = DiscoveredURLStorage(pre_engine)
            await st_pre.create_table()
            js_pre = JobStorage(pre_engine)
            job_id = await js_pre.create(job_type="active", config={"seeds": ["http://127.0.0.1:99999/"]})
            await pre_engine.dispose()

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
            await feed_server.publish("crawl.start", {"job_id": job_id, "config": crawl_config})
            await asyncio.sleep(0.5)

            # Stop it
            await feed_server.publish("crawl.stop", {"job_id": job_id})
            await asyncio.sleep(1.0)

            # Verify we got crawl.started
            assert any(r["topic"] == "crawl.started" for r in results)

            # User-initiated stop must NOT emit crawl.failed (it's not a failure).
            assert not any(r["topic"] == "crawl.failed" for r in results), \
                f"unexpected crawl.failed on user stop: {results}"

            # Verify the job transitioned to "stopped" in crawler.db.
            check_engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}", echo=False)
            try:
                js = JobStorage(check_engine)
                for _ in range(40):
                    job = await js.get(job_id)
                    if job and job["status"] == "stopped":
                        break
                    await asyncio.sleep(0.05)
                assert job is not None
                assert job["status"] == "stopped", f"expected stopped, got {job['status']}"
                assert job["finished_at"] is not None
            finally:
                await check_engine.dispose()

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


# ── 8.8 Engine run() end-to-end: BFS, depth, dedup, max_urls, robots ───────


class FakeFetcher:
    """In-memory fetcher serving canned pages from a dict."""

    def __init__(self, pages: dict[str, str], verify: bool = False, rate_limit: float = 10.0):
        self.pages = pages
        self.verify = verify
        self.rate_limit = rate_limit
        self.fetch_log: list[str] = []

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass

    async def fetch(self, url: str):
        self.fetch_log.append(url)
        body = self.pages.get(url)
        if body is None:
            return None
        return {
            "method": "GET",
            "url": url,
            "request_headers": {},
            "request_body": None,
            "response_headers": {"content-type": "text/html"},
            "response_body": body,
            "response_body_truncated": False,
            "status_code": 200,
            "duration_ms": 1.0,
            "tls": False,
        }


def _run_engine(engine: CrawlEngine, fetcher) -> list[dict]:
    async def _collect():
        out = []
        async for flow in engine.run(fetcher):
            out.append(flow)
        return out

    return asyncio.run(_collect())


class TestCrawlEngineRun:
    BASE = "https://target.com"

    def _scope(self) -> ScopeConfig:
        return _scope(["*://target.com/*"])

    def _pages(self, routes: dict[str, str]) -> dict[str, str]:
        return {f"{self.BASE}{path}": html for path, html in routes.items()}

    def _urls(self, flows: list[dict]) -> set[str]:
        return {f["url"] for f in flows}

    def test_fetches_seed_and_linked_pages(self):
        """Regression: BFS must recurse past the seeds."""
        pages = self._pages({
            "/": '<a href="/a">a</a>',
            "/a": '<a href="/b">b</a>',
            "/b": "leaf",
        })
        engine = CrawlEngine(
            config=CrawlConfig(seeds=[f"{self.BASE}/"], depth=3),
            scope=self._scope(),
        )
        fetcher = FakeFetcher(pages)
        flows = _run_engine(engine, fetcher)
        assert self._urls(flows) == {f"{self.BASE}/", f"{self.BASE}/a", f"{self.BASE}/b"}

    def test_depth_limit_stops_recursion(self):
        pages = self._pages({
            "/": '<a href="/a">a</a>',
            "/a": '<a href="/b">b</a>',
            "/b": "leaf",
        })
        engine = CrawlEngine(
            config=CrawlConfig(seeds=[f"{self.BASE}/"], depth=1),
            scope=self._scope(),
        )
        flows = _run_engine(engine, FakeFetcher(pages))
        assert self._urls(flows) == {f"{self.BASE}/", f"{self.BASE}/a"}

    def test_path_only_dedup_skips_query_variant(self):
        pages = self._pages({
            "/page": '<a href="/page?x=1">self</a> <a href="/other">o</a>',
            "/page?x=1": "dup",
            "/other": "ok",
        })
        engine = CrawlEngine(
            config=CrawlConfig(seeds=[f"{self.BASE}/page"], depth=2),
            scope=self._scope(),
        )
        fetcher = FakeFetcher(pages)
        flows = _run_engine(engine, fetcher)
        assert self._urls(flows) == {f"{self.BASE}/page", f"{self.BASE}/other"}
        assert f"{self.BASE}/page?x=1" not in fetcher.fetch_log

    def test_seed_backlink_not_refetched(self):
        pages = self._pages({
            "/": '<a href="/a">a</a>',
            "/a": '<a href="/">home</a>',
        })
        engine = CrawlEngine(
            config=CrawlConfig(seeds=[f"{self.BASE}/"], depth=3),
            scope=self._scope(),
        )
        fetcher = FakeFetcher(pages)
        flows = _run_engine(engine, fetcher)
        assert self._urls(flows) == {f"{self.BASE}/", f"{self.BASE}/a"}
        assert fetcher.fetch_log.count(f"{self.BASE}/") == 1

    def test_max_urls_backstop_marks_maxed(self):
        pages = self._pages({
            "/": '<a href="/a">a</a>',
            "/a": '<a href="/b">b</a>',
            "/b": "leaf",
        })
        engine = CrawlEngine(
            config=CrawlConfig(seeds=[f"{self.BASE}/"], depth=3, max_urls=1),
            scope=self._scope(),
        )
        fetcher = FakeFetcher(pages)
        flows = _run_engine(engine, fetcher)
        assert len(flows) == 1
        assert engine.stats.fetched == 1
        assert engine.stats.maxed is True
        assert engine.stats.to_dict()["maxed"] is True

    def test_max_urls_not_hit_when_queue_drains(self):
        pages = self._pages({"/": "no links"})
        engine = CrawlEngine(
            config=CrawlConfig(seeds=[f"{self.BASE}/"], depth=2, max_urls=100),
            scope=self._scope(),
        )
        _run_engine(engine, FakeFetcher(pages))
        assert engine.stats.fetched == 1
        assert engine.stats.maxed is False

    def test_out_of_scope_never_fetched(self):
        pages = self._pages({"/": '<a href="https://evil.com/x">evil</a>'})
        engine = CrawlEngine(
            config=CrawlConfig(seeds=[f"{self.BASE}/"], depth=2),
            scope=self._scope(),
        )
        fetcher = FakeFetcher(pages)
        flows = _run_engine(engine, fetcher)
        assert self._urls(flows) == {f"{self.BASE}/"}
        assert not any("evil.com" in u for u in fetcher.fetch_log)

    def test_robots_disallow_blocks_paths(self):
        pages = self._pages({
            "/": '<a href="/admin">a</a> <a href="/public">p</a>',
            "/admin": "secret",
            "/public": "ok",
        })
        engine = CrawlEngine(
            config=CrawlConfig(seeds=[f"{self.BASE}/"], depth=2, respect_robots=True),
            scope=self._scope(),
        )
        fetcher = FakeFetcher(pages)
        with patch(
            "pwnproxy.services.crawler.engine.fetch_robots",
            new=AsyncMock(return_value="User-agent: *\nDisallow: /admin\n"),
        ):
            flows = _run_engine(engine, fetcher)
        assert self._urls(flows) == {f"{self.BASE}/", f"{self.BASE}/public"}
        assert f"{self.BASE}/admin" not in fetcher.fetch_log

    def test_failed_fetch_counts_error(self):
        engine = CrawlEngine(
            config=CrawlConfig(seeds=[f"{self.BASE}/missing"], depth=1),
            scope=self._scope(),
        )
        fetcher = FakeFetcher({})
        flows = _run_engine(engine, fetcher)
        assert flows == []
        assert engine.stats.errors == 1


# ── 8.9 Worker E2E: include_discovered + TLS verify wiring ─────────────────


class TestWorkerCrawlE2EExtended:
    async def _spawn_worker(self, tmp: str, feed_server, extra_args: list[str]):
        db_path = str(Path(tmp) / "crawler.db")
        scope_json = json.dumps({"enabled": False})
        import sys
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "pwnproxy.services.crawler.crawler_worker",
            "--db-path", db_path,
            "--feed-port", str(feed_server.port),
            "--scope-json", scope_json,
            *extra_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        assert proc.stdout is not None
        line = await asyncio.wait_for(proc.stdout.readline(), timeout=30)
        raw = line.decode().strip()
        assert raw.startswith("EVENT_PORT="), f"unexpected worker output: {raw}"
        event_port = int(raw.split("=")[1])
        return proc, db_path, event_port

    async def _run_crawl(self, feed_server, results: list[dict], config: dict, timeout: float = 30.0) -> list[dict]:
        await feed_server.publish("crawl.start", {"job_id": 1, "config": config})
        for _ in range(int(timeout * 20)):
            for r in results:
                if r["topic"] in ("crawl.completed", "crawl.failed"):
                    return results
            await asyncio.sleep(0.05)
        return results

    @pytest.mark.asyncio
    async def test_include_discovered_adds_seeds(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            from pwnproxy.shared.bus.transports.tcp_bridge import TcpBridgeServer, TcpBridgeClient
            from aiohttp import web

            feed_server = TcpBridgeServer()
            await feed_server.start()

            # Local target with two pages.
            app_handler = web.Application()
            app_handler.router.add_get("/", lambda r: web.Response(text="root", content_type="text/html"))
            app_handler.router.add_get("/page2", lambda r: web.Response(text="leaf", content_type="text/html"))
            runner = web.AppRunner(app_handler)
            await runner.setup()
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]

            # Pre-populate discovered_urls with /page2 (what the passive crawler saw).
            db_path = str(Path(tmp) / "crawler.db")
            pre_engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}", echo=False)
            pre_storage = DiscoveredURLStorage(pre_engine)
            await pre_storage.create_table()
            await pre_storage.save(url=f"http://127.0.0.1:{port}/page2")
            await pre_engine.dispose()

            proc, _, event_port = await self._spawn_worker(tmp, feed_server, [])
            results: list[dict] = []
            results_bridge = TcpBridgeClient(
                host="127.0.0.1", port=event_port,
                on_event=lambda t, d: results.append({"topic": t, "data": d}),
            )
            await results_bridge.start()
            await asyncio.sleep(0.3)

            try:
                results = await self._run_crawl(feed_server, results, {
                    "seeds": [f"http://127.0.0.1:{port}/"],
                    "depth": 2,
                    "rate_limit": 50,
                    "concurrency": 5,
                    "max_urls": 10,
                    "include_discovered": True,
                })
                flows = [r for r in results if r["topic"] == "crawler.flow"]
                flow_urls = {r["data"]["url"] for r in flows}
                assert f"http://127.0.0.1:{port}/" in flow_urls, f"seed missing: {flow_urls}"
                assert f"http://127.0.0.1:{port}/page2" in flow_urls, \
                    f"discovered URL not included as seed: {flow_urls}"
            finally:
                await runner.cleanup()
                proc.kill()
                await proc.wait()
                await results_bridge.stop()
                await feed_server.stop()

    def _make_self_signed_cert(self, tmp: str) -> tuple[Path, Path]:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
            .add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        cert_path = Path(tmp) / "cert.pem"
        key_path = Path(tmp) / "key.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        return cert_path, key_path

    @pytest.mark.asyncio
    async def test_tls_ssl_insecure_disables_verification(self):
        """Regression: --ssl-insecure must result in verify=False (insecure).

        Before the fix, ssl_insecure was passed AS verify, inverting the
        semantics and breaking fetches against self-signed targets.
        """
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            from pwnproxy.shared.bus.transports.tcp_bridge import TcpBridgeServer, TcpBridgeClient
            from aiohttp import web

            cert_path, key_path = self._make_self_signed_cert(tmp)

            feed_server = TcpBridgeServer()
            await feed_server.start()

            app_handler = web.Application()
            app_handler.router.add_get("/", lambda r: web.Response(text="secure", content_type="text/html"))
            runner = web.AppRunner(app_handler)
            await runner.setup()
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.load_cert_chain(str(cert_path), str(key_path))
            site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=ssl_ctx)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]

            proc, _, event_port = await self._spawn_worker(tmp, feed_server, ["--ssl-insecure"])
            results: list[dict] = []
            results_bridge = TcpBridgeClient(
                host="127.0.0.1", port=event_port,
                on_event=lambda t, d: results.append({"topic": t, "data": d}),
            )
            await results_bridge.start()
            await asyncio.sleep(0.3)

            try:
                results = await self._run_crawl(feed_server, results, {
                    "seeds": [f"https://127.0.0.1:{port}/"],
                    "depth": 1,
                    "rate_limit": 50,
                    "concurrency": 1,
                    "max_urls": 10,
                })
                completed = [r for r in results if r["topic"] == "crawl.completed"]
                assert completed, f"crawl did not complete: {[r['topic'] for r in results]}"
                assert completed[0]["data"]["fetched"] >= 1, \
                    f"TLS fetch failed despite --ssl-insecure: {completed[0]['data']}"
            finally:
                await runner.cleanup()
                proc.kill()
                await proc.wait()
                await results_bridge.stop()
                await feed_server.stop()

    @pytest.mark.asyncio
    async def test_tls_without_ssl_insecure_verifies(self):
        """Without --ssl-insecure the self-signed fetch must fail (verify=True)."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            from pwnproxy.shared.bus.transports.tcp_bridge import TcpBridgeServer, TcpBridgeClient
            from aiohttp import web

            cert_path, key_path = self._make_self_signed_cert(tmp)

            feed_server = TcpBridgeServer()
            await feed_server.start()

            app_handler = web.Application()
            app_handler.router.add_get("/", lambda r: web.Response(text="secure", content_type="text/html"))
            runner = web.AppRunner(app_handler)
            await runner.setup()
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.load_cert_chain(str(cert_path), str(key_path))
            site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=ssl_ctx)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]

            proc, _, event_port = await self._spawn_worker(tmp, feed_server, [])
            results: list[dict] = []
            results_bridge = TcpBridgeClient(
                host="127.0.0.1", port=event_port,
                on_event=lambda t, d: results.append({"topic": t, "data": d}),
            )
            await results_bridge.start()
            await asyncio.sleep(0.3)

            try:
                results = await self._run_crawl(feed_server, results, {
                    "seeds": [f"https://127.0.0.1:{port}/"],
                    "depth": 1,
                    "rate_limit": 50,
                    "concurrency": 1,
                    "max_urls": 10,
                })
                completed = [r for r in results if r["topic"] == "crawl.completed"]
                assert completed, f"crawl did not complete: {[r['topic'] for r in results]}"
                assert completed[0]["data"]["fetched"] == 0, \
                    "self-signed fetch should have failed with verification on"
                assert completed[0]["data"]["errors"] >= 1
            finally:
                await runner.cleanup()
                proc.kill()
                await proc.wait()
                await results_bridge.stop()
                await feed_server.stop()


# ── 8.10 API: 409 conflict + stop transition ──────────────────────────────


class TestCrawlerAPIConflict:
    @pytest.mark.asyncio
    async def test_start_conflict_409(self):
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
        crawler_mock.running = True
        app.state.crawler_process = crawler_mock

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/crawler/start", json={"seeds": ["https://target.com"]})
        assert resp.status_code == 409
        await engine.dispose()

    @pytest.mark.asyncio
    async def test_stop_marks_job_stopped(self):
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
        crawler_mock.running = True
        crawler_mock.send_to_worker.return_value = True
        app.state.crawler_process = crawler_mock

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/crawler/stop")
        assert resp.status_code == 200
        assert resp.json()["stopped"] is True
        assert resp.json()["job_id"] == jid

        job = await js.get(jid)
        assert job["status"] == "stopped"
        assert job["finished_at"] is not None
        crawler_mock.send_to_worker.assert_called_once_with("crawl.stop", {"job_id": jid})
        await engine.dispose()


# ── 8.11 Re-publish: persist_crawl_flow → traffic.db + flow_stored/done ────


class TestPersistCrawlFlow:
    def _payload(self, **overrides) -> dict:
        payload = {
            "method": "GET",
            "url": "https://target.com/crawled",
            "request_headers": {},
            "request_body": None,
            "response_headers": {"content-type": "text/html"},
            "response_body": "<html>hi</html>",
            "response_body_truncated": False,
            "status_code": 200,
            "duration_ms": 5.0,
            "tls": False,
            "_scan_while_crawl": False,
        }
        payload.update(overrides)
        return payload

    async def _make_engine(self):
        from pwnproxy.shared.db import init_db
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        await init_db(engine)
        return engine

    @pytest.mark.asyncio
    async def test_writes_record_and_publishes_flow_stored(self):
        from pwnproxy.shared.hooks import HookBus
        from pwnproxy.services.crawler.republish import persist_crawl_flow

        engine = await self._make_engine()
        hb = HookBus()
        q_stored = hb.register("flow_stored")
        q_done = hb.register("done")
        try:
            db_id = await persist_crawl_flow(engine, hb, self._payload())
            assert db_id is not None

            stored = await asyncio.wait_for(q_stored.get(), timeout=1.0)
            assert stored["id"] == db_id
            assert stored["url"] == "https://target.com/crawled"

            # scan_while_crawl false → NO done event.
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(q_done.get(), timeout=0.2)

            from pwnproxy.shared.db import FlowRecord
            from sqlalchemy import select
            from sqlalchemy.ext.asyncio import AsyncSession
            from sqlalchemy.orm import sessionmaker
            factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
            async with factory() as session:
                row = (await session.execute(
                    select(FlowRecord).where(FlowRecord.id == db_id)
                )).scalar_one()
                assert row.url == "https://target.com/crawled"
                assert row.response_body == b"<html>hi</html>"
                assert row.status_code == 200
        finally:
            await engine.dispose()

    @pytest.mark.asyncio
    async def test_publishes_done_when_scan_while_crawl(self):
        from pwnproxy.shared.hooks import HookBus
        from pwnproxy.services.crawler.republish import persist_crawl_flow

        engine = await self._make_engine()
        hb = HookBus()
        q_done = hb.register("done")
        try:
            db_id = await persist_crawl_flow(engine, hb, self._payload(_scan_while_crawl=True))
            assert db_id is not None

            done = await asyncio.wait_for(q_done.get(), timeout=1.0)
            assert done["id"] == str(db_id)
            assert done["url"] == "https://target.com/crawled"
            assert done["status_code"] == 200
        finally:
            await engine.dispose()

    @pytest.mark.asyncio
    async def test_returns_none_on_db_error(self):
        from pwnproxy.shared.hooks import HookBus
        from pwnproxy.services.crawler.republish import persist_crawl_flow

        engine = await self._make_engine()
        hb = HookBus()
        await engine.dispose()
        db_id = await persist_crawl_flow(engine, hb, self._payload())
        assert db_id is None
