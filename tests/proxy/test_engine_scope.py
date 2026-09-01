import pytest

from pwnproxy.services.proxy.addons.hook_relay import HookRelayAddon
from pwnproxy.services.proxy.addons.storage import StorageAddon
from pwnproxy.services.proxy.engine import ProxyEngine
from pwnproxy.services.session.manager import ScopeConfig
from pwnproxy.shared.flow_filter import FlowFilter
from pwnproxy.shared.hooks import HookBus


class TestProxyEngineScopeFilter:
    def test_flow_filter_is_shared_across_addons(self):
        filter_ = FlowFilter(ScopeConfig({"enabled": True, "in_scope": ["a.example.com"]}))
        bus = HookBus()
        engine = ProxyEngine(hook_bus=bus, flow_filter=filter_)

        relay = HookRelayAddon(bus, flow_filter=engine.flow_filter)
        storage = StorageAddon(object(), hook_bus=bus, flow_filter=engine.flow_filter)

        assert relay._flow_filter is filter_
        assert storage._flow_filter is filter_

        # Hot-swap the shared filter; both addons see the new scope.
        engine.flow_filter.set_scope(ScopeConfig({"enabled": True, "in_scope": ["b.example.com"]}))
        assert not relay._flow_filter.allow("http://a.example.com/x")
        assert relay._flow_filter.allow("http://b.example.com/x")
        assert not storage._flow_filter.allow("http://a.example.com/x")

    def test_no_filter_keeps_permissive(self):
        bus = HookBus()
        engine = ProxyEngine(hook_bus=bus)
        relay = HookRelayAddon(bus, flow_filter=engine.flow_filter)
        storage = StorageAddon(object(), hook_bus=bus, flow_filter=engine.flow_filter)
        assert relay._flow_filter is None
        assert storage._flow_filter is None
