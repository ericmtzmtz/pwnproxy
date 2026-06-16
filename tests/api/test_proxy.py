import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from pwnproxy.transport.rest.app import app


@pytest.fixture
def test_app():
    # Setup temporary session manager with proxy_config
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        # Mock proxy engine
        proxy_engine = MagicMock()
        proxy_engine.running = False

        # Mock session manager
        session_mgr = MagicMock()
        session_mgr.get_proxy_engine.return_value = proxy_engine
        # Simple proxy config object
        class ProxyConfig:
            def __init__(self):
                self.capture_enabled = False
                self.host = "127.0.0.1"
                self.port = 8080
                self.ssl_insecure = False
                self.upstream = None
        session_mgr.proxy_config = ProxyConfig()
        session_mgr.has_active_session = False
        session_mgr.mark_unsaved = MagicMock()

        app.state.session_manager = session_mgr
        with TestClient(app) as client:
            yield client
        # cleanup automatically

class TestProxyToggle:
    def test_toggle_capture_enabled(self, test_app):
        # initial state should be False
        resp = test_app.put("/api/v1/proxy/toggle")
        assert resp.status_code == 200
        json = resp.json()
        assert json["capture_enabled"] is True

        # second toggle returns to False
        resp = test_app.put("/api/v1/proxy/toggle")
        assert resp.status_code == 200
        json = resp.json()
        assert json["capture_enabled"] is False
