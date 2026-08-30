import tempfile
from pathlib import Path

import pytest

from pwnproxy.services.session.manager import ScopeConfig, SessionManager, SESSIONS_ROOT


@pytest.fixture
def mock_sessions_root(monkeypatch, tmp_path):
    monkeypatch.setattr("pwnproxy.services.session.manager.SESSIONS_ROOT", tmp_path)
    monkeypatch.setattr("pwnproxy.services.session.manager.LAST_SESSION_FILE", tmp_path / ".last_session")
    return tmp_path


class TestScopeConfig:
    def test_enabled_false_passes_all(self):
        scope = ScopeConfig({"enabled": False, "in_scope": ["*.target.com"]})
        assert scope.is_in_scope("https://evil.com/test")

    def test_in_scope_matches_domain(self):
        scope = ScopeConfig({"enabled": True, "in_scope": ["*.target.com"]})
        assert scope.is_in_scope("https://api.target.com/endpoint")
        assert not scope.is_in_scope("https://evil.com/test")

    def test_in_scope_matches_url_pattern(self):
        scope = ScopeConfig({"enabled": True, "in_scope": ["https://api.target.com/*"]})
        assert scope.is_in_scope("https://api.target.com/v1/users")
        assert not scope.is_in_scope("https://other.target.com/test")

    def test_out_of_scope_excludes(self):
        scope = ScopeConfig({
            "enabled": True,
            "in_scope": ["*.target.com"],
            "out_of_scope": ["https://analytics.target.com/*"],
        })
        assert scope.is_in_scope("https://api.target.com/endpoint")
        assert not scope.is_in_scope("https://analytics.target.com/report")

    def test_no_in_scope_patterns_passes_all(self):
        scope = ScopeConfig({"enabled": True, "in_scope": []})
        assert scope.is_in_scope("https://anything.com/test")

    def test_to_dict_roundtrip(self):
        data = {
            "enabled": True,
            "in_scope": ["*.target.com"],
            "out_of_scope": ["https://ads.target.com"],
        }
        scope = ScopeConfig(data)
        assert scope.to_dict() == data

    def test_to_dict_ignores_dead_fields(self):
        data = {
            "enabled": True,
            "in_scope": ["*.target.com"],
            "out_of_scope": [],
            "include_subdomains": True,
            "ports": [80, 443],
        }
        scope = ScopeConfig(data)
        result = scope.to_dict()
        assert "include_subdomains" not in result
        assert "ports" not in result


def test_list_empty(mock_sessions_root):
    assert SessionManager.list() == []


def test_list_after_create(mock_sessions_root):
    session_dir = mock_sessions_root / "test-session"
    session_dir.mkdir(parents=True)
    (session_dir / "session.json").write_text('{"name": "test-session", "version": 1}')

    result = SessionManager.list()
    names = [s["name"] for s in result]
    assert "test-session" in names


def test_scope_config_url_without_scheme(mock_sessions_root):
    scope = ScopeConfig({"enabled": True, "in_scope": ["*.target.com"]})
    assert not scope.is_in_scope("http://evil.com/test")
    assert scope.is_in_scope("http://sub.target.com/test")


class TestUpdateScopeOwnerAPI:
    """SessionManager.update_scope is the single scope write point (ownership
    matrix). It must mutate config, persist, and fire the change handler."""

    def _manager(self, monkeypatch, tmp_path):
        from unittest.mock import AsyncMock
        import asyncio
        from pwnproxy.services.session.manager import LAST_SESSION_FILE
        monkeypatch.setattr("pwnproxy.services.session.manager.SESSIONS_ROOT", tmp_path)
        monkeypatch.setattr("pwnproxy.services.session.manager.LAST_SESSION_FILE", tmp_path / ".last_session")
        m = SessionManager.__new__(SessionManager)
        m._active_name = "s"
        m._active_path = tmp_path / "s"
        m._save_lock = asyncio.Lock()
        m._traffic_engine = AsyncMock()
        m._scanner_engine = AsyncMock()
        m._token_storage = AsyncMock()
        m._on_scope_change = None
        m.scope = ScopeConfig()
        m.save = AsyncMock()
        return m

    @pytest.mark.asyncio
    async def test_update_scope_mutates_and_saves(self, monkeypatch, tmp_path):
        m = self._manager(monkeypatch, tmp_path)
        result = await m.update_scope({"in_scope": ["https://x.com/*"], "enabled": True})
        assert m.scope.in_scope == ["https://x.com/*"]
        assert result["in_scope"] == ["https://x.com/*"]
        m.save.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_update_scope_fires_handler(self, monkeypatch, tmp_path):
        from unittest.mock import AsyncMock
        m = self._manager(monkeypatch, tmp_path)
        handler = AsyncMock()
        m._on_scope_change = handler
        await m.update_scope({"in_scope": ["https://z.com/*"]})
        handler.assert_awaited_once()
        assert handler.call_args[0][0]["in_scope"] == ["https://z.com/*"]

    @pytest.mark.asyncio
    async def test_update_scope_handler_error_does_not_raise(self, monkeypatch, tmp_path):
        from unittest.mock import AsyncMock
        m = self._manager(monkeypatch, tmp_path)
        m._on_scope_change = AsyncMock(side_effect=RuntimeError("boom"))
        result = await m.update_scope({"enabled": False})
        assert result["enabled"] is False
