"""Config injection and parity tests through the real loader path."""
import pytest
from pwnproxy.plugins.core.chain import BudgetChain, DetectionDepth

@pytest.mark.asyncio
async def test_build_scan_loader_injects_config():
    """_build_scan_loader with config builds plugins that see the config."""
    from apps.terminal.cli.scan import _build_scan_loader
    loader = await _build_scan_loader(config={"depth": "standard", "evasion_level": "light"})
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
    from apps.terminal.cli.scan import _build_scan_loader
    loader = await _build_scan_loader(config={})
    sqli = loader.get_plugin("sqli")
    chain = getattr(sqli._scanner, "_chain", getattr(sqli._scanner, "chain", None))
    assert chain._max_depth == DetectionDepth.FAST
    assert chain._budget_ms == BudgetChain.BUDGET_MS[DetectionDepth.FAST]
    for name in list(loader.list_plugins()):
        await loader.unload(name)


@pytest.mark.asyncio
async def test_discover_vs_standalone_parity():
    """Live discovery and standalone loader must expose the same scanner names."""
    from pwnproxy.plugins.core.loader import PluginLoader
    from apps.terminal.cli.scan import _build_scan_loader
    # discovered via loader.discover_scanners()
    loader_disc = PluginLoader()
    await loader_disc.discover_scanners()
    disc_names = set(loader_disc.list_plugins())
    for n in list(loader_disc.list_plugins()):
        await loader_disc.unload(n)

    loader_standalone = await _build_scan_loader()
    stand_names = set(loader_standalone.list_plugins())
    for n in list(loader_standalone.list_plugins()):
        await loader_standalone.unload(n)

    assert disc_names == stand_names, f"discover {disc_names} vs standalone {stand_names}"
    # ensure command-injection is present on both sides
    assert "command-injection" in stand_names
