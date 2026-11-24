"""``GET /sessions/scope`` and ``GET /workers`` publish the auto-scan verdict.

The Web UI never recomputes the rule: it renders ``active_scan_allowed`` and the
sentence in ``active_scan_blocked_reason``. These tests pin both fields (and the
exact wording) in the three states of the scope.
"""

from unittest.mock import MagicMock

import pytest

from pwnproxy.services.session.manager import ScopeConfig
from pwnproxy.transport.rest.app import app

SCOPE_OFF = "Scope is off: active scanners only run on in-scope traffic. Turn the scope on."
NO_RULES = "Scope has no include rules: add at least one target to scan."

#: The two fields under test, per scope state.
OFF = {"active_scan_allowed": False, "active_scan_blocked_reason": SCOPE_OFF}
ON_WITHOUT_RULES = {"active_scan_allowed": False, "active_scan_blocked_reason": NO_RULES}
ON_WITH_RULE = {"active_scan_allowed": True, "active_scan_blocked_reason": None}


@pytest.fixture
def scan_status_client(api_client):
    """API client over a session manager whose scope the test controls."""

    def build(scope: ScopeConfig):
        manager = MagicMock()
        manager.active_name = "juice-shop"
        manager.scope = scope
        manager.get_crawler_engine.return_value = None
        manager.get_proxy_engine.return_value = None
        app.state.session_manager = manager
        app.state.task_store = None
        app.state.crawler_process = None
        app.state.autoscan_tracker = None
        return api_client(app)

    yield build

    for attribute in ("session_manager", "task_store", "crawler_process", "autoscan_tracker"):
        if hasattr(app.state, attribute):
            delattr(app.state, attribute)


class TestScopeEndpointPublishesTheVerdict:
    def test_scope_off(self, scan_status_client):
        scope = ScopeConfig({"enabled": False, "in_scope": ["localhost:3000"]})
        with scan_status_client(scope) as client:
            response = client.get("/api/v1/sessions/scope")

        assert (response.status_code, response.json()) == (
            200,
            {
                "in_scope": ["localhost:3000"],
                "out_of_scope": [],
                "enabled": False,
                **OFF,
            },
        )

    def test_scope_on_without_include_rules(self, scan_status_client):
        scope = ScopeConfig({"enabled": True, "in_scope": []})
        with scan_status_client(scope) as client:
            response = client.get("/api/v1/sessions/scope")

        assert (response.status_code, response.json()) == (
            200,
            {"in_scope": [], "out_of_scope": [], "enabled": True, **ON_WITHOUT_RULES},
        )

    def test_scope_on_with_a_rule(self, scan_status_client):
        scope = ScopeConfig({"enabled": True, "in_scope": ["localhost:3000"]})
        with scan_status_client(scope) as client:
            response = client.get("/api/v1/sessions/scope")

        assert (response.status_code, response.json()) == (
            200,
            {
                "in_scope": ["localhost:3000"],
                "out_of_scope": [],
                "enabled": True,
                **ON_WITH_RULE,
            },
        )


class TestWorkersEndpointPublishesTheVerdict:
    def _body(self, verdict: dict) -> dict:
        return {
            "tasks": [],
            "crawler_jobs": [],
            "autoscan": {"running": False, "active": None, "last": None},
            "proxy": {"running": False, "port": None, "capture_enabled": False},
            **verdict,
        }

    def test_scope_off(self, scan_status_client):
        with scan_status_client(ScopeConfig({"enabled": False, "in_scope": []})) as client:
            response = client.get("/api/v1/workers")

        assert (response.status_code, response.json()) == (200, self._body(OFF))

    def test_scope_on_without_include_rules(self, scan_status_client):
        with scan_status_client(ScopeConfig({"enabled": True, "in_scope": []})) as client:
            response = client.get("/api/v1/workers")

        assert (response.status_code, response.json()) == (200, self._body(ON_WITHOUT_RULES))

    def test_scope_on_with_a_rule(self, scan_status_client):
        with scan_status_client(ScopeConfig({"enabled": True, "in_scope": ["localhost:3000"]})) as client:
            response = client.get("/api/v1/workers")

        assert (response.status_code, response.json()) == (200, self._body(ON_WITH_RULE))
