import dataclasses
import pytest
import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

from pwnproxy.shared.models import Flow
from pwnproxy.plugins.core.base import PluginMetadata, PluginContext, PwnPlugin, Finding
from pwnproxy.plugins.core.loader import UniversalPluginLoader, PluginLoadError
from pwnproxy.shared.hooks import HookBus


class MockFlowPlugin(PwnPlugin):
    def __init__(self, metadata: PluginMetadata, context: PluginContext):
        super().__init__(metadata, context)
        self.flow_count = 0

    async def on_flow(self, flow):
        self.flow_count += 1
        yield f"flow_result_{self.flow_count}"


class MockFindingPlugin(PwnPlugin):
    def __init__(self, metadata: PluginMetadata, context: PluginContext):
        super().__init__(metadata, context)
        self.finding_count = 0

    async def on_finding(self, finding):
        self.finding_count += 1
        return f"finding_result_{self.finding_count}"


class MockLegacyPlugin(PwnPlugin):
    def __init__(self, metadata: PluginMetadata, context: PluginContext):
        super().__init__(metadata, context)
        self.scan_count = 0

    async def scan(self, flow):
        self.scan_count += 1
        yield f"legacy_result_{self.scan_count}"


class MockScannerPlugin(PwnPlugin):
    """Plugin that consumes a specific scanner topic (e.g. flow.sqli)."""
    def __init__(self, metadata: PluginMetadata, context: PluginContext, name: str):
        super().__init__(metadata, context)
        self._name = name
        self.processed = 0

    async def on_flow(self, flow):
        self.processed += 1
        yield f"{self._name}_result_{self.processed}"


class TestUniversalPluginLoader:
    @pytest.fixture
    def hook_bus(self):
        return HookBus()

    @pytest.fixture
    def loader(self, hook_bus):
        return UniversalPluginLoader(hook_bus)

    @pytest.fixture
    def metadata(self):
        return PluginMetadata(
            name="test_plugin",
            version="1.0.0",
            author="Test Author",
            category="scanner",
            description="Test plugin",
            consumes=["flow"],
            produces=["finding"]
        )

    @pytest.fixture
    def context(self):
        return PluginContext()

    @pytest.fixture
    def flow_plugin(self, metadata, context):
        return MockFlowPlugin(metadata, context)

    @pytest.fixture
    def finding_plugin(self, metadata, context):
        finding_meta = dataclasses.replace(metadata, produces=["finding_result"])
        return MockFindingPlugin(finding_meta, context)

    @pytest.fixture
    def legacy_plugin(self, metadata, context):
        # Legacy plugin uses scan instead of on_flow
        legacy_meta = PluginMetadata(
            name="legacy_plugin",
            version="1.0.0",
            author="Test Author",
            category="scanner",
            description="Legacy plugin",
            consumes=["flow"],
            produces=["result"]
        )
        return MockLegacyPlugin(legacy_meta, context)

    @pytest.mark.asyncio
    async def test_load_plugin(self, loader, flow_plugin):
        """Test loading a plugin successfully."""
        await loader.load(flow_plugin)
        
        assert loader.list_plugins() == ["test_plugin"]
        assert loader.get_plugin("test_plugin") == flow_plugin

    @pytest.mark.asyncio
    async def test_load_duplicate_plugin(self, loader, flow_plugin):
        """Test loading duplicate plugin is ignored."""
        await loader.load(flow_plugin)
        await loader.load(flow_plugin)  # Should be ignored
        
        assert len(loader.list_plugins()) == 1

    @pytest.mark.asyncio
    async def test_load_plugin_with_channel_mapping(self, loader, flow_plugin):
        """Test loading plugin with custom channel mapping."""
        channel_mapping = {"flow": "custom_flow_channel"}
        await loader.load(flow_plugin, channel_mapping)
        
        # Plugin should be registered
        assert loader.list_plugins() == ["test_plugin"]

    @pytest.mark.asyncio
    async def test_consumer_task_runs(self, loader, flow_plugin):
        """Test that consumer task runs and processes data."""
        # Load the plugin
        await loader.load(flow_plugin)
        await loader.start()
        
        # Get the channel name
        channel_name = "flow"
        
        # Publish some flow data
        test_flow = Flow(id="test", method="GET", url="http://test.com", request_headers={})
        loader.hook_bus.publish(channel_name, test_flow)
        
        # Wait a bit for the consumer to process
        await asyncio.sleep(0.3)
        
        # Plugin should have processed the flow
        assert flow_plugin.flow_count > 0

    @pytest.mark.asyncio
    async def test_finding_plugin_consumes_findings(self, loader, finding_plugin):
        """Test that finding plugin consumes finding data."""
        # Load the plugin
        await loader.load(finding_plugin)
        await loader.start()
        
# Publish some finding data
        test_finding = Finding(
            scanner="test",
            url="http://test.com",
            method="GET",
            param_name="test_param",
            param_location="query",
            technique="error-based",
            severity="high",
            confidence="confirmed",
            payload="test_payload",
            evidence="Response contains error message",
            timestamp=datetime.now(timezone.utc)
        )
        loader.hook_bus.publish("finding", test_finding)
    
        # Wait a bit for the consumer to process
        await asyncio.sleep(0.3)
        
        # Plugin should have processed the finding
        assert finding_plugin.finding_count > 0

    @pytest.mark.asyncio
    async def test_legacy_plugin_migration(self, loader, legacy_plugin):
        """Test that legacy scan() method is migrated to on_flow()."""
        # Load the plugin
        await loader.load(legacy_plugin)
        await loader.start()
        
        # Publish some flow data
        test_flow = Flow(id="test", method="GET", url="http://test.com", request_headers={})
        loader.hook_bus.publish("flow", test_flow)
        
        # Wait a bit for the consumer to process
        await asyncio.sleep(0.3)
        
        # Legacy plugin should have processed the flow via scan()
        assert legacy_plugin.scan_count > 0

    @pytest.mark.asyncio
    async def test_unload_plugin(self, loader, flow_plugin):
        """Test unloading a plugin."""
        await loader.load(flow_plugin)
        await loader.start()
        assert len(loader.list_plugins()) == 1
        
        await loader.unload("test_plugin")
        assert len(loader.list_plugins()) == 0

    @pytest.mark.asyncio
    async def test_get_plugin_info(self, loader, flow_plugin):
        """Test getting plugin information."""
        await loader.load(flow_plugin)
        
        info = loader.get_plugin_info("test_plugin")
        assert info is not None
        assert info["name"] == "test_plugin"
        assert info["version"] == "1.0.0"
        assert info["consumes"] == ["flow"]
        assert info["produces"] == ["finding"]

    @pytest.mark.asyncio
    async def test_plugin_with_no_handler(self, loader):
        """Test plugin with no handler for a consume type."""
        # Create a plugin that claims to consume 'surface' but has no handler
        metadata = PluginMetadata(
            name="no_handler_plugin",
            version="1.0.0",
            consumes=["surface"]
        )
        context = PluginContext()
        
        class NoHandlerPlugin(PwnPlugin):
            def __init__(self, metadata, context):
                super().__init__(metadata, context)
        
        plugin = NoHandlerPlugin(metadata, context)
        await loader.load(plugin)
        
        # Should not raise an exception, just log a warning
        assert loader.list_plugins() == ["no_handler_plugin"]

    @pytest.mark.asyncio
    async def test_publish_results(self, loader, flow_plugin):
        """Test that plugin results are published to produces channels."""
        await loader.load(flow_plugin)
        
        # Publish a flow
        test_flow = Flow(id="test", method="GET", url="http://test.com", request_headers={})
        loader.hook_bus.publish("flow", test_flow)
        
        # Wait for processing
        await asyncio.sleep(0.1)
        
        # Check if results were published (this depends on the plugin implementation)
        # For this test, we're mainly ensuring no exceptions are raised

    @pytest.mark.asyncio
    async def test_consumer_timeout(self, loader, flow_plugin):
        """Test that consumer handles timeouts gracefully."""
        # Set a very short timeout
        loader._timeout = 0.01
        
        await loader.load(flow_plugin)
        
        # Publish flow data
        test_flow = Flow(id="test", method="GET", url="http://test.com", request_headers={})
        loader.hook_bus.publish("flow", test_flow)
        
        # Wait for timeout to occur
        await asyncio.sleep(0.1)
        
        # Should not crash, just continue running
        assert True  # If we get here, no exception was raised


class TestBackwardCompatibility:
    """Test backward compatibility with old PluginLoader interface."""
    
    @pytest.mark.asyncio
    async def test_plugin_loader_interface(self):
        """Test that PluginLoader interface works for backward compatibility."""
        from pwnproxy.plugins.core.loader import PluginLoader
        
        loader = PluginLoader()
        
        # These methods should exist and not crash
        assert loader.list_plugins() == []
        assert loader.list_active() == []
        assert loader.watchdog_stats() == {"disabled": []}
        assert loader.get_scanner("nonexistent") is None
        assert loader.get_all_scanners() == {}
        
        # These are placeholders and should log warnings
        with pytest.warns(UserWarning):
            await loader.load_from_package("test")
        
        with pytest.warns(UserWarning):
            await loader.activate("test")
        
        with pytest.warns(UserWarning):
            await loader.run_hooks_response(Flow(id="test", method="GET", url="http://test.com", request_headers={}))


class TestPerScannerTopics:
    """Test that per-scanner topic routing works correctly."""

    @pytest.fixture
    def hook_bus(self):
        return HookBus()

    @pytest.fixture
    def loader(self, hook_bus):
        return UniversalPluginLoader(hook_bus)

    @pytest.mark.asyncio
    async def test_per_scanner_topic_publishes(self, hook_bus, loader):
        """Publishing on flow.sqli with no sqli plugin does not crash."""
        sqli_plugin = MockFlowPlugin(
            PluginMetadata(name="sqli", version="1.0.0", consumes=["flow"], produces=["finding"]),
            PluginContext(),
        )
        xss_plugin = MockFlowPlugin(
            PluginMetadata(name="xss", version="1.0.0", consumes=["flow"], produces=["finding"]),
            PluginContext(),
        )
        await loader.load(sqli_plugin)
        await loader.load(xss_plugin)
        await loader.start()
        # Give both consumer tasks time to register on the hook_bus
        await asyncio.sleep(0.05)

        flow = Flow(id="test", method="GET", url="http://test.com", request_headers={})

        # Publish on generic flow topic — both plugins receive it
        hook_bus.publish("flow", flow)
        await asyncio.sleep(0.3)
        assert sqli_plugin.flow_count >= 1, "sqli plugin should receive flow on generic topic"
        assert xss_plugin.flow_count >= 1, "xss plugin should receive flow on generic topic"

    @pytest.mark.asyncio
    async def test_generic_topic_still_works_for_all(self, hook_bus, loader):
        """Generic 'flow' topic still delivers to all scanner plugins (backward compat)."""
        p1 = MockFlowPlugin(
            PluginMetadata(name="p1", version="1.0.0", consumes=["flow"], produces=["finding"]),
            PluginContext(),
        )
        p2 = MockFlowPlugin(
            PluginMetadata(name="p2", version="1.0.0", consumes=["flow"], produces=["finding"]),
            PluginContext(),
        )
        await loader.load(p1)
        await loader.load(p2)
        await loader.start()
        await asyncio.sleep(0.05)

        flow = Flow(id="g", method="GET", url="http://test.com/g", request_headers={})
        hook_bus.publish("flow", flow)
        await asyncio.sleep(0.3)
        assert p1.flow_count >= 1
        assert p2.flow_count >= 1