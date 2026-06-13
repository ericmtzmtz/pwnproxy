import pytest
from fastapi.testclient import TestClient

from pwnproxy.transport.rest.app import app
from pwnproxy.shared.hooks import HookBus


@pytest.fixture
def test_app():
    hook_bus = HookBus()
    app.state.hook_bus = hook_bus
    app.state.plugin_loader = None
    app.state.proxy_port = 19999

    with TestClient(app) as client:
        yield client


class TestHealth:
    def test_health_returns_200(self, test_app):
        response = test_app.get("/api/v1/health")
        assert response.status_code == 200

    def test_health_response_shape(self, test_app):
        response = test_app.get("/api/v1/health")
        data = response.json()
        assert "status" in data
        assert "version" in data
        assert "checks" in data

    def test_health_checks_has_all_keys(self, test_app):
        response = test_app.get("/api/v1/health")
        checks = response.json()["checks"]
        for key in ("api", "proxy", "scanners", "plugins"):
            assert key in checks
            assert "status" in checks[key]
            assert "message" in checks[key]

    def test_health_api_is_ok(self, test_app):
        response = test_app.get("/api/v1/health")
        assert response.json()["checks"]["api"]["status"] == "ok"

    def test_health_version_present(self, test_app):
        response = test_app.get("/api/v1/health")
        assert isinstance(response.json()["version"], str)
        assert len(response.json()["version"]) > 0

    def test_health_proxy_down_when_not_running(self, test_app):
        response = test_app.get("/api/v1/health")
        assert response.json()["checks"]["proxy"]["status"] == "down"
