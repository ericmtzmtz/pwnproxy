from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from pwnproxy.transport.rest.app import app
from pwnproxy.services.session.manager import ScopeConfig, SESSIONS_ROOT, LAST_SESSION_FILE


@pytest.fixture
def test_client(monkeypatch, tmp_path):
    manager = MagicMock()
    manager.active_name = "test-session"
    manager.active_path = tmp_path / "test-session"
    manager.has_unsaved_changes = False
    manager.scope = ScopeConfig()
    manager.list.return_value = [
        {"name": "test-session", "created_at": "2026-01-01", "last_modified": "2026-01-02"},
        {"name": "other-session", "created_at": "2026-01-03", "last_modified": "2026-01-04"},
    ]

    app.state.session_manager = manager
    app.state.plugin_loader = None
    app.state.proxy_port = 19999
    from pwnproxy.shared.hooks import HookBus
    app.state.hook_bus = HookBus()

    for s in ["test-session", "other-session"]:
        p = tmp_path / s
        p.mkdir(parents=True, exist_ok=True)
        (p / "traffic.db").write_text("x" * 100)
        (p / "scanner_results.db").write_text("x" * 50)

    last_file = tmp_path / ".last_session"
    last_file.write_text("test-session")

    monkeypatch.setattr("pwnproxy.services.session.manager.SESSIONS_ROOT", tmp_path)
    monkeypatch.setattr("pwnproxy.services.session.manager.LAST_SESSION_FILE", last_file)

    with TestClient(app) as client:
        yield client


class TestSessionList:
    def test_lists_sessions(self, test_client):
        resp = test_client.get("/api/v1/sessions")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2
        names = [s["name"] for s in data]
        assert "test-session" in names
        assert "other-session" in names

    def test_includes_metadata(self, test_client):
        resp = test_client.get("/api/v1/sessions")
        data = resp.json()
        for s in data:
            assert "request_count" in s
            assert "finding_count" in s
            assert "last_active" in s
            assert "created_at" in s
            assert "last_modified" in s
            assert "active" in s

    def test_db_sizes(self, test_client):
        resp = test_client.get("/api/v1/sessions")
        data = resp.json()
        for s in data:
            assert s["request_count"] > 0
            assert s["finding_count"] > 0

    def test_last_active_flag(self, test_client):
        resp = test_client.get("/api/v1/sessions")
        data = resp.json()
        for s in data:
            if s["name"] == "test-session":
                assert s["last_active"] is True
            else:
                assert s["last_active"] is False


class TestScopeAPI:
    @pytest.fixture
    def scope_client(self, test_client):
        manager = app.state.session_manager
        manager.save = AsyncMock()
        manager.get_proxy_engine.return_value = None
        return test_client

    def test_update_scope_valid_strings(self, scope_client):
        resp = scope_client.put(
            "/api/v1/sessions/scope",
            json={"in_scope": ["http://127.0.0.1:9999/*"], "out_of_scope": [], "enabled": True},
        )
        assert resp.status_code == 200
        scope = app.state.session_manager.scope
        assert scope.in_scope == ["http://127.0.0.1:9999/*"]
        assert scope.enabled is True
        app.state.session_manager.save.assert_awaited_once()

    def test_update_scope_rejects_dict_patterns(self, scope_client):
        # Regression: structured dicts used to be stored verbatim and later
        # crash ScopeConfig.is_in_scope inside fnmatch (TypeError → 500).
        resp = scope_client.put(
            "/api/v1/sessions/scope",
            json={
                "enabled": True,
                "in_scope": [{"host": "127.0.0.1", "protocol": "http", "port": 9999, "path": "/"}],
                "out_of_scope": [],
            },
        )
        assert resp.status_code == 422

    def test_update_scope_rejects_non_string_entries(self, scope_client):
        resp = scope_client.put(
            "/api/v1/sessions/scope",
            json={"in_scope": ["http://ok.com/*", 42], "enabled": True},
        )
        assert resp.status_code == 422

    def test_update_scope_legacy_patterns_alias(self, scope_client):
        resp = scope_client.put("/api/v1/sessions/scope", json={"patterns": ["https://x.com/*"]})
        assert resp.status_code == 200
        assert app.state.session_manager.scope.in_scope == ["https://x.com/*"]

    def test_update_scope_auto_enable(self, scope_client):
        resp = scope_client.put("/api/v1/sessions/scope", json={"in_scope": ["https://y.com/*"]})
        assert resp.status_code == 200
        assert app.state.session_manager.scope.enabled is True

    def test_update_scope_disable_only(self, scope_client):
        resp = scope_client.put("/api/v1/sessions/scope", json={"enabled": False})
        assert resp.status_code == 200
        assert app.state.session_manager.scope.enabled is False
        assert app.state.session_manager.scope.in_scope == []
