"""Tests for plugin interface - async generators and compatibility shim."""
import asyncio
from collections.abc import AsyncGenerator
from unittest.mock import MagicMock

import pytest

from pwnproxy.shared.models import Flow
from pwnproxy.plugins.core.base import Finding, ScannerPlugin
from pwnproxy.plugins.core.loader import PluginLoader


class MockFlow:
    """Minimal flow for testing."""
    def __init__(self):
        self.id = "test-flow-1"
        self.method = "GET"
        self.url = "http://example.com/?q=test"
        self.request_headers = {"Host": "example.com"}
        self.request_body = None
        self.status_code = 200
        self.response_headers = {}
        self.response_body = b"<html>test</html>"
        self.tls = False
        self.duration_ms = 100.0
        self.error = None


class NewStyleScannerPlugin(ScannerPlugin):
    """New-style plugin using async generator."""
    name = "new-style"
    version = "1.0.0"
    author = "test"
    category = "scanner"

    def __init__(self, findings_to_yield: list[Finding] | None = None):
        self._findings = findings_to_yield or []

    async def on_flow(
        self,
        flow,
    ) -> AsyncGenerator[Finding, None]:
        for finding in self._findings:
            yield finding


@pytest.mark.asyncio
async def test_new_style_plugin_yields_findings():
    """New-style plugin should yield findings via async generator."""
    findings = [
        Finding(
            scanner="test",
            url="http://example.com",
            method="GET",
            param_name="q",
            param_location="query",
            technique="error-based",
            severity="high",
            confidence="confirmed",
            payload="' OR 1=1--",
            evidence="Test evidence",
        )
    ]
    plugin = NewStyleScannerPlugin(findings)
    flow = MockFlow()

    results = []
    async for finding in plugin.on_flow(flow):
        results.append(finding)

    assert len(results) == 1
    assert results[0].scanner == "test"
    assert results[0].technique == "error-based"


@pytest.mark.asyncio
async def test_new_style_plugin_yields_multiple_findings():
    """New-style plugin should yield multiple findings."""
    findings = [
        Finding(
            scanner="test",
            url="http://example.com",
            method="GET",
            param_name="q",
            param_location="query",
            technique="error-based",
            severity="high",
            confidence="confirmed",
            payload="' OR 1=1--",
            evidence="Test evidence",
        ),
        Finding(
            scanner="test",
            url="http://example.com",
            method="GET",
            param_name="q",
            param_location="query",
            technique="time-based-blind",
            severity="high",
            confidence="confirmed",
            payload="' AND SLEEP(5)--",
            evidence="Test evidence",
        ),
    ]
    plugin = NewStyleScannerPlugin(findings)
    flow = MockFlow()

    results = []
    async for finding in plugin.on_flow(flow):
        results.append(finding)

    assert len(results) == 2
    assert results[0].technique == "error-based"
    assert results[1].technique == "time-based-blind"


@pytest.mark.asyncio
async def test_new_style_plugin_yields_nothing():
    """New-style plugin with no findings should yield nothing."""
    plugin = NewStyleScannerPlugin([])
    flow = MockFlow()

    results = []
    async for finding in plugin.on_flow(flow):
        results.append(finding)

    assert len(results) == 0


@pytest.mark.asyncio
async def test_plugin_loader_handles_new_style():
    """PluginLoader should handle new-style async generator plugins."""
    finding = Finding(
        scanner="test",
        url="http://example.com",
        method="GET",
        param_name="q",
        param_location="query",
        technique="error-based",
        severity="high",
        confidence="confirmed",
        payload="' OR 1=1--",
        evidence="Test evidence",
    )
    plugin = NewStyleScannerPlugin([finding])
    
    loader = PluginLoader()
    await loader.load_builtin(plugin)
    
    flow = MockFlow()
    results = await loader.run_scan(flow)
    
    assert len(results) == 1
    assert results[0].scanner == "test"





@pytest.mark.asyncio
async def test_plugin_loader_passes_depth_and_evasion():
    """PluginLoader should pass depth and evasion_level to plugins."""
    finding = Finding(
        scanner="test",
        url="http://example.com",
        method="GET",
        param_name="q",
        param_location="query",
        technique="error-based",
        severity="high",
        confidence="confirmed",
        payload="' OR 1=1--",
        evidence="Test evidence",
    )
    plugin = NewStyleScannerPlugin([finding])
    
    loader = PluginLoader()
    await loader.load_builtin(plugin)
    
    flow = MockFlow()
    # Test with different depth and evasion_level
    results = await loader.run_scan(flow, depth="deep", evasion_level="aggressive")
    
    assert len(results) == 1
    assert results[0].scanner == "test"


@pytest.mark.asyncio
async def test_scanner_plugin_capabilities_match_techniques():
    """Each scanner's capabilities should cover its techniques."""
    from pwnproxy.plugins.scanners.sqli.plugin import SQLiScannerPlugin
    from pwnproxy.plugins.scanners.xss.plugin import XSSScannerPlugin
    from pwnproxy.plugins.scanners.lfi.plugin import LFIScannerPlugin
    from pwnproxy.plugins.scanners.xxe.plugin import XXEScannerPlugin
    from pwnproxy.plugins.scanners.ssrf.plugin import SSRFScannerPlugin

    plugins = [SQLiScannerPlugin(), XSSScannerPlugin(), LFIScannerPlugin(),
               XXEScannerPlugin(), SSRFScannerPlugin()]

    for plugin in plugins:
        assert hasattr(plugin, "capabilities"), f"{plugin.name} missing capabilities"
        assert isinstance(plugin.capabilities, list), f"{plugin.name} capabilities not a list"
        assert len(plugin.capabilities) > 0, f"{plugin.name} has empty capabilities"
        assert hasattr(plugin, "techniques"), f"{plugin.name} missing techniques"
        assert isinstance(plugin.techniques, list), f"{plugin.name} techniques not a list"
        assert len(plugin.techniques) > 0, f"{plugin.name} has empty techniques"
