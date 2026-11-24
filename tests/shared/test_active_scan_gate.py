"""The auto-scan rule: scope on, at least one include rule, URL in scope.

These are the unit tests of the single decision the backend owns
(``ScopeConfig.active_scan_allowed`` / ``active_scan_blocked_reason``) and of
``FlowFilter.allow_active_scan``, the seam every delivery path uses. The
sentences are asserted literally: they are part of the contract published by
``GET /sessions/scope`` and ``GET /workers`` and shown by the Web UI.
"""

from pwnproxy.services.session.manager import ScopeConfig
from pwnproxy.shared.flow_filter import FlowFilter

SCOPE_OFF = "Scope is off: active scanners only run on in-scope traffic. Turn the scope on."
NO_RULES = "Scope has no include rules: add at least one target to scan."


class TestScopeActiveScanVerdict:
    def test_scope_off_is_blocked_with_its_reason(self):
        config = ScopeConfig({"enabled": False, "in_scope": ["*.example.com"]})

        assert (config.active_scan_allowed(), config.active_scan_blocked_reason()) == (
            False,
            SCOPE_OFF,
        )

    def test_scope_on_without_include_rules_is_blocked(self):
        config = ScopeConfig({"enabled": True, "in_scope": []})

        assert (config.active_scan_allowed(), config.active_scan_blocked_reason()) == (
            False,
            NO_RULES,
        )

    def test_scope_on_with_a_rule_is_allowed_and_has_no_reason(self):
        config = ScopeConfig({"enabled": True, "in_scope": ["*.example.com"]})

        assert (config.active_scan_allowed(), config.active_scan_blocked_reason()) == (
            True,
            None,
        )

    def test_default_scope_is_off_and_blocks(self):
        """A fresh session has no scope: nothing may be actively scanned."""
        config = ScopeConfig()

        assert (config.enabled, config.in_scope, config.active_scan_blocked_reason()) == (
            False,
            [],
            SCOPE_OFF,
        )


class TestFlowFilterActiveScan:
    def test_scope_off_blocks_active_scan_while_capture_keeps_working(self):
        """The two questions are different: capture yes, active scan no."""
        flow_filter = FlowFilter(ScopeConfig({"enabled": False, "in_scope": ["*.example.com"]}))

        assert (
            flow_filter.allow("https://content-autofill.googleapis.com/v1/pages"),
            flow_filter.allow_active_scan("https://content-autofill.googleapis.com/v1/pages"),
            flow_filter.active_scan_blocked_reason(),
        ) == (True, False, SCOPE_OFF)

    def test_scope_on_without_rules_blocks_active_scan(self):
        flow_filter = FlowFilter(ScopeConfig({"enabled": True, "in_scope": []}))

        assert (
            flow_filter.allow_active_scan("http://localhost:3000/rest/user/login"),
            flow_filter.active_scan_blocked_reason(),
        ) == (False, NO_RULES)

    def test_scope_on_with_a_matching_rule_allows_active_scan(self):
        flow_filter = FlowFilter(ScopeConfig({"enabled": True, "in_scope": ["localhost:3000"]}))

        assert (
            flow_filter.allow_active_scan("http://localhost:3000/rest/user/login"),
            flow_filter.active_scan_blocked_reason(),
        ) == (True, None)

    def test_scope_on_but_url_out_of_scope_blocks_active_scan(self):
        flow_filter = FlowFilter(ScopeConfig({"enabled": True, "in_scope": ["localhost:3000"]}))

        assert flow_filter.allow_active_scan("https://content-autofill.googleapis.com/v1/pages") is False

    def test_turning_the_scope_on_at_runtime_allows_the_next_flow(self):
        """No restart: the shared filter holds a reference, not a snapshot."""
        flow_filter = FlowFilter(ScopeConfig({"enabled": False, "in_scope": []}))
        assert flow_filter.allow_active_scan("http://localhost:3000/rest/user/login") is False

        flow_filter.set_scope(ScopeConfig({"enabled": True, "in_scope": ["localhost:3000"]}))

        assert flow_filter.allow_active_scan("http://localhost:3000/rest/user/login") is True

    def test_filter_follows_the_session_scope_that_replaces_itself(self):
        """The REST path swaps ``SessionManager.scope``: a snapshot would go stale.

        This is the wiring the main process uses (``scope_provider`` =
        ``SessionManager.get_scope``), so a scope change applies to the very next
        flow without restarting anything.
        """

        class Owner:
            def __init__(self):
                self.scope = ScopeConfig({"enabled": False, "in_scope": []})

            def get_scope(self):
                return self.scope

        owner = Owner()
        flow_filter = FlowFilter(owner.scope, scope_provider=owner.get_scope)
        assert flow_filter.allow_active_scan("http://localhost:3000/rest/user/login") is False

        owner.scope = ScopeConfig({"enabled": True, "in_scope": ["localhost:3000"]})

        assert flow_filter.allow_active_scan("http://localhost:3000/rest/user/login") is True
