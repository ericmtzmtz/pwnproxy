from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from pwnproxy.api.main import app
from pwnproxy.modules.session_manager.manager import ScopeConfig, SESSIONS_ROOT, LAST_SESSION_FILE


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
    from pwnproxy.core.hooks import HookBus
    app.state.hook_bus = HookBus()

    for s in ["test-session", "other-session"]:
        p = tmp_path / s
        p.mkdir(parents=True, exist_ok=True)
        (p / "traffic.db").write_text("x" * 100)
        (p / "scanner_results.db").write_text("x" * 50)

    last_file = tmp_path / ".last_session"
    last_file.write_text("test-session")

    monkeypatch.setattr("pwnproxy.modules.session_manager.manager.SESSIONS_ROOT", tmp_path)
    monkeypatch.setattr("pwnproxy.modules.session_manager.manager.LAST_SESSION_FILE", last_file)

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
