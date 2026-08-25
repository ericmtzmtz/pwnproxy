"""Crawler tests: extractor, normalización, scope, storage, API/WS, worker E2E."""
import asyncio
import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine

from pwnproxy.services.crawler.extractor import (
    extract_from_headers,
    extract_urls,
    normalize_url,
)
from pwnproxy.services.crawler.storage import DiscoveredURLStorage
from pwnproxy.services.session.manager import ScopeConfig


# ── Helpers ──────────────────────────────────────────────────────────────


def _scope(patterns: list[str], out: list[str] | None = None) -> ScopeConfig:
    return ScopeConfig({
        "enabled": bool(patterns),
        "in_scope": patterns,
        "out_of_scope": out or [],
    })


def _make_flow(url: str = "https://target.com/page", body: str = "<a href='/x'>",
               method: str = "GET") -> dict:
    """Build a proxy.flow dict as it arrives over the bridge."""
    return {
        "id": "flow-test",
        "url": url,
        "method": method,
        "request_headers": {},
        "response_headers": {},
        "response_body": body,
        "status_code": 200,
    }


async def _make_storage(tmpdir: str | None = None):
    if tmpdir:
        path = Path(tmpdir) / "crawler.db"
    else:
        path = Path("/dev/null")  # unused with :memory:
        path = None
    if path is not None:
        url = f"sqlite+aiosqlite:///{path}"
    else:
        url = "sqlite+aiosqlite:///:memory:"
    engine = create_async_engine(url, echo=False)
    st = DiscoveredURLStorage(engine)
    await st.create_table()
    return engine, st


# ── 7.1 Unit extractor ──────────────────────────────────────────────────


class TestExtractor:
    BASE = "https://target.com/app/page"

    def test_html_a_href(self):
        res = extract_urls('<a href="/about">x</a>', self.BASE)
        assert ("https://target.com/about", "a") in res

    def test_html_form_action(self):
        res = extract_urls('<form action="/submit">', self.BASE)
        assert any(u == "https://target.com/submit" and s == "form" for u, s in res)

    def test_html_script_src(self):
        res = extract_urls('<script src="/app.js"></script>', self.BASE)
        assert any(u.endswith("/app.js") and s == "script" for u, s in res)

    def test_html_img_src(self):
        res = extract_urls('<img src="logo.png">', self.BASE)
        assert any("/logo.png" in u and s == "img" for u, s in res)

    def test_location_header(self):
        res = extract_from_headers({"Location": "/login?next=/dashboard"}, self.BASE)
        assert any("/login?next=/dashboard" in u and s == "location" for u, s in res)

    def test_content_location_header(self):
        res = extract_from_headers({"Content-Location": "/api/v1"}, self.BASE)
        assert any("/api/v1" in u and s == "location" for u, s in res)

    def test_js_fetch_relative(self):
        res = extract_urls('<script>fetch("/api/users");</script>', self.BASE)
        assert any("/api/users" in u and s == "js" for u, s in res)

    def test_js_absolute_url(self):
        res = extract_urls(
            '<script>var u="https://cdn.target.com/lib.js";</script>',
            self.BASE,
        )
        assert any("cdn.target.com" in u and s == "js" for u, s in res)

    def test_json_relative_url(self):
        res = extract_urls(
            '{"next": "/api?page=2", "url": "https://x.com/a/"}',
            self.BASE,
            "application/json",
        )
        urls = [u for u, _ in res]
        assert "https://x.com/a" in urls
        assert "https://target.com/api?page=2" in urls

    def test_empty_body_returns_empty(self):
        assert extract_urls(None, self.BASE) == []
        assert extract_urls("", self.BASE) == []

    def test_dedup_within_page(self):
        res = extract_urls(
            '<a href="/x"><a href="/x">',
            self.BASE,
        )
        assert len([u for u, _ in res if u.endswith("/x")]) == 1

    def test_form_action_relative(self):
        res = extract_urls('<form action="login">', self.BASE)
        assert any("/app/login" in u and s == "form" for u, s in res)


# ── 7.2 Unit normalización/dedup ────────────────────────────────────────


class TestNormalize:
    BASE = "https://target.com/app/page"

    def test_trailing_slash_removed(self):
        assert normalize_url("https://target.com/about/", self.BASE) == "https://target.com/about"

    def test_root_trailing_slash_kept(self):
        assert normalize_url("https://target.com/", self.BASE) == "https://target.com/"

    def test_fragment_removed(self):
        assert normalize_url("https://target.com/page#sec", self.BASE) == "https://target.com/page"

    def test_query_sorted(self):
        result = normalize_url("https://target.com/?b=2&a=1", self.BASE)
        assert result == "https://target.com/?a=1&b=2"

    def test_query_preserves_raw_encoding(self):
        result = normalize_url("https://target.com/?next=/dash", self.BASE)
        assert result == "https://target.com/?next=/dash"

    def test_protocol_relative(self):
        result = normalize_url("//other.com/path", "https://target.com/x")
        assert result == "https://other.com/path"

    def test_javascript_uri_rejected(self):
        assert normalize_url("javascript:alert(1)", self.BASE) is None

    def test_mailto_rejected(self):
        assert normalize_url("mailto:x@y.com", self.BASE) is None

    def test_fragment_only_rejected(self):
        assert normalize_url("#sec", self.BASE) is None

    def test_empty_input_rejected(self):
        assert normalize_url("", self.BASE) is None
        assert normalize_url("  ", self.BASE) is None

    def test_lowercase_host(self):
        result = normalize_url("https://TARGET.COM/path", self.BASE)
        assert result == "https://target.com/path"


# ── 7.3 Unit scope filter ───────────────────────────────────────────────


class TestScopeFilter:
    def test_in_scope_url_passes(self):
        scope = _scope(["*://target.com/*"])
        assert scope.is_in_scope("https://target.com/api/v1") is True

    def test_out_of_scope_url_rejected(self):
        scope = _scope(["*://target.com/*"])
        assert scope.is_in_scope("https://evil.com/steal") is False

    def test_disabled_scope_passes_all(self):
        scope = ScopeConfig({"enabled": False})
        assert scope.is_in_scope("http://anything.com/") is True

    def test_empty_scope_passes_all(self):
        scope = ScopeConfig({"enabled": True, "in_scope": []})
        assert scope.is_in_scope("http://anything.com/") is True

    def test_out_of_scope_takes_precedence(self):
        scope = _scope(["*://target.com/*"], out=["*://target.com/internal*"])
        assert scope.is_in_scope("https://target.com/internal/secret") is False
        assert scope.is_in_scope("https://target.com/public") is True


# ── 7.4 Storage: save + dedup, list + filter ────────────────────────────


class TestStorage:
    @pytest.mark.asyncio
    async def test_save_returns_id(self):
        engine, st = await _make_storage()
        try:
            rid = await st.save("/api", source="a", method="GET", base_url="https://x.com")
            assert rid is not None
            assert rid >= 1
        finally:
            await engine.dispose()

    @pytest.mark.asyncio
    async def test_save_dedup_returns_none(self):
        engine, st = await _make_storage()
        try:
            i1 = await st.save("/a", source="a", base_url="https://x.com")
            i2 = await st.save("/a", source="a", base_url="https://x.com")
            assert i1 is not None
            assert i2 is None
            assert await st.count() == 1
        finally:
            await engine.dispose()

    @pytest.mark.asyncio
    async def test_list_paginated(self):
        engine, st = await _make_storage()
        try:
            for i in range(25):
                await st.save(f"/p{i}", source="a", base_url="https://x.com")
            p1 = await st.list(limit=10, offset=0)
            p2 = await st.list(limit=10, offset=10)
            assert len(p1) == 10
            assert len(p2) == 10
            assert await st.count() == 25
        finally:
            await engine.dispose()

    @pytest.mark.asyncio
    async def test_list_source_filter(self):
        engine, st = await _make_storage()
        try:
            await st.save("/a", source="a", base_url="https://x.com")
            await st.save("/f", source="form", base_url="https://x.com")
            a_only = await st.list(source="a")
            assert len(a_only) == 1
            assert a_only[0]["source"] == "a"
        finally:
            await engine.dispose()


# ── 7.5 API: GET /crawler/urls + WS event ──────────────────────────────


class TestApiCrawler:
    @pytest.mark.asyncio
    async def test_list_urls_empty(self):
        from pwnproxy.transport.rest.app import app
        client = TestClient(app, raise_server_exceptions=False)
        # Mock session_manager with a real storage engine
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        st = DiscoveredURLStorage(engine)
        await st.create_table()

        sm = MagicMock()
        sm.get_crawler_engine.return_value = engine
        app.state.session_manager = sm
        app.state.crawler_process = MagicMock(return_value={"running": False})

        resp = client.get("/api/v1/crawler/urls")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["total"] == 0
        await engine.dispose()

    @pytest.mark.asyncio
    async def test_list_urls_with_data(self):
        from pwnproxy.transport.rest.app import app
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        st = DiscoveredURLStorage(engine)
        await st.create_table()
        await st.save("/api", source="a", base_url="https://x.com")
        await st.save("/form", source="form", base_url="https://x.com")

        sm = MagicMock()
        sm.get_crawler_engine.return_value = engine
        app.state.session_manager = sm
        app.state.crawler_process = MagicMock(return_value={"running": False})

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/crawler/urls")
        data = resp.json()
        assert data["total"] == 2
        await engine.dispose()

    @pytest.mark.asyncio
    async def test_crawler_status(self):
        from pwnproxy.transport.rest.app import app
        crawler_mock = MagicMock()
        crawler_mock.status.return_value = {"running": True, "pid": 12345}
        app.state.crawler_process = crawler_mock

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/crawler/status")
        assert resp.json()["running"] is True
        assert resp.json()["pid"] == 12345


# ── 7.6 E2E worker subprocess ──────────────────────────────────────────


class TestWorkerE2E:
    @pytest.mark.asyncio
    async def test_spawn_worker_and_feed_flow(self):
        """Spawn crawler worker, feed a response with links, verify row persisted."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            db_path = str(Path(tmp) / "crawler.db")
            scope_json = json.dumps({"enabled": False})
            # We need a feed port. Start a TcpBridgeServer to act as the main process feed.
            from pwnproxy.shared.bus.transports.tcp_bridge import TcpBridgeServer
            feed_server = TcpBridgeServer()
            await feed_server.start()
            feed_port = feed_server.port

            # Spawn the actual crawler worker subprocess
            import sys
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-m", "pwnproxy.services.crawler.crawler_worker",
                "--db-path", db_path,
                "--feed-port", str(feed_port),
                "--scope-json", scope_json,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            # Read EVENT_PORT from worker
            assert proc.stdout is not None
            line = await asyncio.wait_for(proc.stdout.readline(), timeout=30)
            raw = line.decode().strip()
            assert raw.startswith("EVENT_PORT=")
            event_port = int(raw.split("=")[1])

            # Connect to results bridge to capture crawler.url events
            from pwnproxy.shared.bus.transports.tcp_bridge import TcpBridgeClient
            results: list[dict] = []

            def _on_result(topic, data):
                results.append({"topic": topic, "data": data})

            results_bridge = TcpBridgeClient(host="127.0.0.1", port=event_port, on_event=_on_result)
            await results_bridge.start()
            await asyncio.sleep(0.2)

            # Feed a flow with a link
            flow = _make_flow(body='<a href="/new-page">link</a>')
            await feed_server.publish("crawler.feed", flow)

            # Poll DB until row appears (up to 15s)
            engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}", echo=False)
            st = DiscoveredURLStorage(engine)
            found = False
            for _ in range(300):
                rows = await st.list(limit=100)
                if any(r["url"].endswith("/new-page") for r in rows):
                    found = True
                    break
                await asyncio.sleep(0.05)
            await engine.dispose()

            assert found, "Worker should persist discovered URL from fed flow"

            # Verify results bridge received crawler.url event
            assert any(r["topic"] == "crawler.url" for r in results)

            # Clean up
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
            await results_bridge.stop()
            await feed_server.stop()

    @pytest.mark.asyncio
    async def test_worker_crash_does_not_affect_main(self):
        """Kill the crawler worker, main process components keep working."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            from pwnproxy.shared.bus.transports.tcp_bridge import TcpBridgeServer
            feed_server = TcpBridgeServer()
            await feed_server.start()

            import sys
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-m", "pwnproxy.services.crawler.crawler_worker",
                "--db-path", str(Path(tmp) / "crawler.db"),
                "--feed-port", str(feed_server.port),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            assert proc.stdout is not None
            line = await asyncio.wait_for(proc.stdout.readline(), timeout=30)
            assert line.decode().startswith("EVENT_PORT=")

            # Kill the worker
            proc.kill()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                pass

            # Main process feed server still works (publish to no clients = no error)
            await feed_server.publish("crawler.feed", _make_flow())
            assert proc.returncode != 0  # process is dead
            await feed_server.stop()

    @pytest.mark.asyncio
    async def test_scope_blocks_out_of_scope_flow(self):
        """Worker skips out-of-scope base URLs."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            from pwnproxy.shared.bus.transports.tcp_bridge import TcpBridgeServer
            feed_server = TcpBridgeServer()
            await feed_server.start()

            scope_json = json.dumps({"enabled": True, "in_scope": ["*://target.com/*"], "out_of_scope": []})
            import sys
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-m", "pwnproxy.services.crawler.crawler_worker",
                "--db-path", str(Path(tmp) / "crawler.db"),
                "--feed-port", str(feed_server.port),
                "--scope-json", scope_json,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            assert proc.stdout is not None
            line = await asyncio.wait_for(proc.stdout.readline(), timeout=30)
            assert line.decode().startswith("EVENT_PORT=")
            await asyncio.sleep(0.2)

            # Feed an out-of-scope flow
            flow = _make_flow(url="https://evil.com/x", body="<a href='/z'>")
            await feed_server.publish("crawler.feed", flow)
            await asyncio.sleep(1.0)

            engine = create_async_engine(f"sqlite+aiosqlite:///{Path(tmp) / 'crawler.db'}", echo=False)
            st = DiscoveredURLStorage(engine)
            rows = await st.list()
            assert len(rows) == 0  # nothing persisted
            await engine.dispose()

            proc.kill()
            await proc.wait()
            await feed_server.stop()
