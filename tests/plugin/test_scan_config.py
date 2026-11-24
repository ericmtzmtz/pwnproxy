"""Config injection and parity tests through the real loader path."""
from unittest.mock import MagicMock

import httpx
import pytest

from pwnproxy.plugins.core.chain import BudgetChain, DetectionDepth


@pytest.mark.asyncio
async def test_build_scan_loader_injects_config():
    """build_scan_loader with config builds plugins that see the config."""
    from pwnproxy.plugins.core.catalog import build_scan_loader

    loader = await build_scan_loader(config={"depth": "standard", "evasion_level": "light"})
    # sqli has BudgetChain; check depth ceiling
    sqli = loader.get_plugin("sqli")
    assert sqli is not None
    # SQLiScanner stores chain as _chain
    chain = getattr(sqli._scanner, "_chain", getattr(sqli._scanner, "chain", None))
    assert chain is not None
    assert chain._max_depth == DetectionDepth.STANDARD
    assert chain.depth == DetectionDepth.FAST
    assert chain._budget_ms == BudgetChain.BUDGET_MS[DetectionDepth.STANDARD]
    assert sqli.context.config["depth"] == "standard"
    assert sqli.context.config["evasion_level"] == "light"
    for name in list(loader.list_plugins()):
        await loader.unload(name)


@pytest.mark.asyncio
async def test_build_scan_loader_default_is_fast():
    """Without config the loader defaults to fast/none."""
    from pwnproxy.plugins.core.catalog import build_scan_loader

    loader = await build_scan_loader(config={})
    sqli = loader.get_plugin("sqli")
    chain = getattr(sqli._scanner, "_chain", getattr(sqli._scanner, "chain", None))
    assert chain._max_depth == DetectionDepth.FAST
    assert chain._budget_ms == BudgetChain.BUDGET_MS[DetectionDepth.FAST]
    for name in list(loader.list_plugins()):
        await loader.unload(name)


@pytest.mark.asyncio
async def test_discover_vs_standalone_parity():
    """Live discovery and standalone loader must expose the same scanner names."""
    from pwnproxy.plugins.core.catalog import build_scan_loader
    from pwnproxy.plugins.core.loader import PluginLoader

    # discovered via loader.discover_scanners()
    loader_disc = PluginLoader()
    await loader_disc.discover_scanners()
    disc_names = set(loader_disc.list_plugins())
    for n in list(loader_disc.list_plugins()):
        await loader_disc.unload(n)

    loader_standalone = await build_scan_loader()
    stand_names = set(loader_standalone.list_plugins())
    for n in list(loader_standalone.list_plugins()):
        await loader_standalone.unload(n)

    assert disc_names == stand_names, f"discover {disc_names} vs standalone {stand_names}"
    # ensure command-injection is present on both sides
    assert "command-injection" in stand_names


class _ScriptedReplayer:
    """Answers a fake vulnerable endpoint: the scan runs with no network at all.

    Same surface the sqli stages use (``send_clean``/``replay``/
    ``build_payload_request``), so the loader path under test is the production
    one — only the transport is replaced.
    """

    def __init__(self) -> None:
        self.payloads: list[str] = []

    async def send_clean(self, point, timeout=10.0):
        return self._response("<html>nothing to see</html>")

    async def replay(self, point, payload, timeout=3.0, evasion_level="none"):
        self.payloads.append(payload)
        return self._response("<html>You have an error in your SQL syntax</html>")

    def build_payload_request(self, point, payload, evasion_level="none"):
        return httpx.Request(point.method, point.url)

    async def close(self) -> None:
        """What ``on_unload`` calls; the real replayer closes its httpx client."""

    @staticmethod
    def _response(text: str) -> MagicMock:
        response = MagicMock()
        response.status_code = 200
        response.text = text
        response.headers = {}
        return response


@pytest.mark.asyncio
async def test_a_builtin_scanner_still_scans_through_the_loader(monkeypatch):
    """Compatibility (``plugin-config-api``): the scan path did not change.

    A shipped scanner is loaded by ``build_scan_loader``, it declares **no**
    configuration schema (so the new API leaves it untouched) and it still
    produces a confirmed finding of its own technique.

    The patch goes on ``pwnproxy.shared.scan.replayer`` and not on the plugin's
    module: ``build_scan_loader`` discovers a built-in with
    ``spec_from_file_location`` + ``exec_module``, so the plugin module is
    executed **again** and its ``from … import RequestReplayer`` reads whatever
    the source module holds at that moment.
    """
    import pwnproxy.shared.scan.replayer as replayer_module
    from pwnproxy.plugins.core.catalog import build_scan_loader
    from pwnproxy.shared.models import Flow

    monkeypatch.setattr(replayer_module, "RequestReplayer", _ScriptedReplayer)
    loader = await build_scan_loader(
        scanners={"sqli"}, config={"depth": "fast", "evasion_level": "none"}
    )
    plugin = loader.get_plugin("sqli")
    flow = Flow(
        id="flow-1",
        method="GET",
        url="http://target.local/sqli/?id=1",
        request_headers={"Host": "target.local"},
    )
    findings = await loader.run_scan(flow)
    loaded = sorted(loader.list_plugins())
    for name in list(loader.list_plugins()):
        await loader.unload(name)

    assert (
        loaded,
        getattr(plugin, "config_schema", None),
        [(finding.scanner, finding.technique, finding.confidence) for finding in findings],
    ) == (["sqli"], None, [("sqli", "error-based", "confirmed")])

