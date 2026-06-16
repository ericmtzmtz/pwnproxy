import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from pwnproxy.services.proxy.proxy_process import ProxyProcess
from pwnproxy.services.session.manager import ProxyConfig, ScopeConfig, SessionManager
from pwnproxy.shared.db import Base, FlowRecord


class TestProxyProcessArgs:
    @pytest.mark.asyncio
    async def test_start_without_db_or_scope(self):
        proc = ProxyProcess()
        config = ProxyConfig({"host": "127.0.0.1", "port": 8080})
        mock_proc = AsyncMock()
        mock_proc.stdout.readline = AsyncMock(return_value=b"EVENT_PORT=9999\n")
        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=mock_proc)):
            await proc.start(config)
        assert proc._event_port == 9999

    @pytest.mark.asyncio
    async def test_start_with_db_path(self):
        proc = ProxyProcess()
        config = ProxyConfig({"host": "127.0.0.1", "port": 8080})
        mock_proc = AsyncMock()
        mock_proc.stdout.readline = AsyncMock(return_value=b"EVENT_PORT=9999\n")
        with patch("asyncio.create_subprocess_exec") as mock_create:
            mock_create.return_value = mock_proc
            await proc.start(config, db_path="/tmp/session/traffic.db")
            args, _ = mock_create.call_args
        assert "--db-path" in args
        idx = args.index("--db-path")
        assert args[idx + 1] == "/tmp/session/traffic.db"

    @pytest.mark.asyncio
    async def test_start_with_scope_patterns(self):
        proc = ProxyProcess()
        config = ProxyConfig({"host": "127.0.0.1", "port": 8080})
        mock_proc = AsyncMock()
        mock_proc.stdout.readline = AsyncMock(return_value=b"EVENT_PORT=9999\n")
        scope = ["*://example.com/*", "*://*.example.com/*"]
        with patch("asyncio.create_subprocess_exec") as mock_create:
            mock_create.return_value = mock_proc
            await proc.start(config, scope=scope)
            args, _ = mock_create.call_args
        assert "--scope-enabled" in args
        assert args.count("--scope-pattern") == 2
        idx1 = args.index("--scope-pattern")
        assert args[idx1 + 1] == "*://example.com/*"
        idx2 = args.index("--scope-pattern", idx1 + 1)
        assert args[idx2 + 1] == "*://*.example.com/*"

    @pytest.mark.asyncio
    async def test_restart_forwards_db_and_scope(self):
        proc = ProxyProcess()
        config = ProxyConfig({"host": "127.0.0.1", "port": 8080})
        with patch.object(proc, "stop", AsyncMock()) as mock_stop:
            with patch.object(proc, "start", AsyncMock()) as mock_start:
                await proc.restart(config, db_path="/db", scope=["*://x.com/*"])
                mock_stop.assert_awaited_once()
                mock_start.assert_awaited_once_with(
                    config, db_path="/db", scope=["*://x.com/*"], scope_json=None
                )


class TestSessionManagerApplyProxyConfig:
    @pytest.fixture
    def manager(self):
        sm = SessionManager(
            traffic_engine=MagicMock(),
            scanner_engine=MagicMock(),
            token_storage=MagicMock(),
        )
        sm._proxy_engine = AsyncMock()
        sm._proxy_engine.restart = AsyncMock()
        sm._proxy_engine.running = False
        sm._active_name = "test-session"
        sm._active_path = MagicMock()
        sm._active_path.__truediv__ = lambda self, other: MagicMock(
            __str__=lambda s: f"/sessions/test-session/{other}"
        )
        sm.scope = ScopeConfig()
        sm.proxy_config = ProxyConfig()
        return sm

    @pytest.mark.asyncio
    async def test_does_not_auto_start_proxy(self, manager):
        await manager._apply_proxy_config()
        manager._proxy_engine.restart.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_skips_when_no_proxy_engine(self, manager):
        manager._proxy_engine = None
        await manager._apply_proxy_config()
        pass


@pytest.mark.asyncio
class TestSessionAtoBIsolation:
    """Integration: flows stored in session A's DB are invisible to session B."""

    async def _make_engine_and_seed(self, db_path: str, flows: list[dict]) -> None:
        engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with factory() as session:
            for f in flows:
                session.add(FlowRecord(**f))
            await session.commit()
        await engine.dispose()

    async def _count_flows(self, db_path: str) -> int:
        engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
        factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with factory() as session:
            result = await session.execute(select(FlowRecord))
            count = len(result.scalars().all())
        await engine.dispose()
        return count

    async def test_session_a_and_b_have_separate_databases(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            db_a = str(Path(tmp) / "session_a" / "traffic.db")
            db_b = str(Path(tmp) / "session_b" / "traffic.db")
            Path(db_a).parent.mkdir(parents=True)
            Path(db_b).parent.mkdir(parents=True)

            await self._make_engine_and_seed(db_a, [
                dict(method="GET", url="http://example.com/a",
                     request_headers={"Host": "example.com"},
                     status_code=200),
            ])
            await self._make_engine_and_seed(db_b, [
                dict(method="POST", url="http://example.com/b",
                     request_headers={"Host": "example.com"},
                     status_code=201),
                dict(method="GET", url="http://other.com/",
                     request_headers={"Host": "other.com"},
                     status_code=200),
            ])

            assert await self._count_flows(db_a) == 1
            assert await self._count_flows(db_b) == 2

    async def test_switch_back_to_a_preserves_original_flows(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            db_a = str(Path(tmp) / "session_a" / "traffic.db")
            db_b = str(Path(tmp) / "session_b" / "traffic.db")
            Path(db_a).parent.mkdir(parents=True)
            Path(db_b).parent.mkdir(parents=True)

            await self._make_engine_and_seed(db_a, [
                dict(method="GET", url="http://a.com/1",
                     request_headers={"Host": "a.com"},
                     status_code=200),
                dict(method="GET", url="http://a.com/2",
                     request_headers={"Host": "a.com"},
                     status_code=200),
            ])
            assert await self._count_flows(db_a) == 2

            await self._make_engine_and_seed(db_b, [
                dict(method="GET", url="http://b.com/1",
                     request_headers={"Host": "b.com"},
                     status_code=200),
            ])
            assert await self._count_flows(db_a) == 2
            assert await self._count_flows(db_b) == 1


class TestScopeFilterCapture:
    """Integration: scope_filter callback in proxy_worker filters flows at capture time."""

    def _make_args(self, scope_enabled=True, scope_pattern=None):
        import argparse
        return argparse.Namespace(
            scope_enabled=scope_enabled,
            scope_pattern=scope_pattern or [],
            scope_json=None,
            listen_host="127.0.0.1", listen_port=8080,
            ssl_insecure=True, upstream=None,
            capture_enabled=True, db_path=None, confdir="~/.mitmproxy",
        )

    def test_scope_check_passes_in_scope(self):
        from pwnproxy.services.proxy.proxy_worker import ProxyWorker
        worker = ProxyWorker(self._make_args(
            scope_enabled=True,
            scope_pattern=["*://allowed.example.com/*"],
        ))
        assert worker._scope_filter("http://allowed.example.com/path") is True

    def test_scope_check_blocks_out_of_scope(self):
        from pwnproxy.services.proxy.proxy_worker import ProxyWorker
        worker = ProxyWorker(self._make_args(
            scope_enabled=True,
            scope_pattern=["*://allowed.example.com/*"],
        ))
        assert worker._scope_filter("http://evil.com/") is False

    def test_scope_check_passes_when_disabled(self):
        from pwnproxy.services.proxy.proxy_worker import ProxyWorker
        worker = ProxyWorker(self._make_args(scope_enabled=False))
        assert worker._scope_filter("http://anything.com/") is True
