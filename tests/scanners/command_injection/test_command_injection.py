"""Golden command-injection test through the real loader path.

Runs the real CommandInjectionScannerPlugin over the in-process fixture and
asserts detection on the injectable endpoint and no finding on the safe one.
"""

import contextlib
import importlib.util
from pathlib import Path

import pytest

_GOLDEN_DIR = Path(__file__).resolve().parents[2] / "golden"


def _load_target_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, _GOLDEN_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def _run(url: str, flow_id: str) -> list:
    from pwnproxy.plugins.core.loader import PluginLoader
    from pwnproxy.plugins.scanners.command_injection.plugin import (
        CommandInjectionScannerPlugin,
    )
    from pwnproxy.shared.models import Flow

    loader = PluginLoader()
    plugin = CommandInjectionScannerPlugin()
    await loader.load_builtin(plugin, config={"depth": "fast", "evasion_level": "none"})
    try:
        flow = Flow(id=flow_id, method="GET", url=url, request_headers={}, request_body=None)
        return await loader.run_scan(flow)
    finally:
        with contextlib.suppress(Exception):
            await loader.unload(plugin.metadata.name)


@pytest.mark.golden
class TestGoldenCommandInjection:
    @pytest.fixture(scope="class")
    def target(self):
        module = _load_target_module("golden_cmd_target", "command_injection_target.py")
        t = module.CommandInjectionTargetServer()
        t.start()
        yield t
        t.stop()

    @pytest.mark.asyncio
    async def test_finding_on_injectable_endpoint(self, target):
        findings = await _run(f"{target.base_url}/cmd?cmd=1", "golden-cmd-injectable")
        assert any(f.scanner == "command-injection" for f in findings), (
            f"no command-injection finding: {[(f.scanner, f.technique) for f in findings]}"
        )

    @pytest.mark.asyncio
    async def test_zero_findings_on_safe(self, target):
        findings = await _run(f"{target.base_url}/safe?cmd=1", "golden-cmd-safe")
        assert [f for f in findings if f.scanner == "command-injection"] == [], (
            f"false positive on /safe: {[(f.scanner, f.technique) for f in findings]}"
        )
