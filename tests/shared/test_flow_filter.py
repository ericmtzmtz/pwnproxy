import pytest
from pwnproxy.services.session.manager import ScopeConfig
from pwnproxy.shared.flow_filter import FlowFilter

class TestFlowFilter:
    @pytest.fixture
    def filter_with_scope(self):
        scope = ScopeConfig({"enabled": True, "in_scope": ["*.example.com"]})
        return FlowFilter(scope)

    def test_allow_in_scope(self, filter_with_scope):
        assert filter_with_scope.allow("http://api.example.com/test")

    def test_block_out_of_scope(self, filter_with_scope):
        assert not filter_with_scope.allow("http://evil.com/test")

    def test_block_when_capture_disabled(self, filter_with_scope):
        filter_with_scope.set_capture_enabled(False)
        assert not filter_with_scope.allow("http://api.example.com/test")

    def test_allow_when_capture_reenabled(self, filter_with_scope):
        filter_with_scope.set_capture_enabled(False)
        filter_with_scope.set_capture_enabled(True)
        assert filter_with_scope.allow("http://api.example.com/test")

    def test_allow_when_scope_disabled(self):
        scope = ScopeConfig({"enabled": False, "in_scope": ["*.example.com"]})
        f = FlowFilter(scope)
        assert f.allow("http://evil.com/test")

    def test_capture_enabled_default(self):
        scope = ScopeConfig()
        f = FlowFilter(scope)
        assert f.capture_enabled is True

    def test_set_scope_changes_verdict_without_rebuild(self):
        f = FlowFilter(ScopeConfig({"enabled": True, "in_scope": ["a.example.com"]}))
        assert f.allow("http://a.example.com/x")
        assert not f.allow("http://b.example.com/x")

        f.set_scope(ScopeConfig({"enabled": True, "in_scope": ["b.example.com"]}))
        assert not f.allow("http://a.example.com/x")
        assert f.allow("http://b.example.com/x")

    def test_set_scope_keeps_capture_enabled_state(self):
        f = FlowFilter(ScopeConfig({"enabled": True, "in_scope": ["a.example.com"]}))
        f.set_capture_enabled(False)
        f.set_scope(ScopeConfig({"enabled": True, "in_scope": ["b.example.com"]}))
        assert not f.allow("http://b.example.com/x")
