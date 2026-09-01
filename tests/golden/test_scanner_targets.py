"""Golden scanner-target tests against the deterministic in-process fixtures.

These run the REAL scanner plugins (SQLi + XSS) over HTTP against the
``tests/golden/sqli_target.py`` and ``tests/golden/xss_target.py`` fixtures and
assert the accuracy promises of the scanner-accuracy change:

- 0 findings on ``/sqli/safe`` and ``/sqli/noisy`` (no FP on clean/noisy input)
- 1 boolean-blind finding on ``/sqli/boolean``
- 0 reflected XSS on escaped endpoints (``/attr-safe``, ``/safe``)
- reflected XSS on breakout endpoints (``/attr``, ``/reflect``, ``/js``, ``/comment``)
- escaped-but-reflected input yields ``unescaped-reflection`` (low / tentative),
  never ``reflected-xss``.

Marked ``@pytest.mark.golden``:
    poetry run pytest -m golden
"""

import importlib.util
from pathlib import Path

import pytest

_GOLDEN_DIR = Path(__file__).parent


def _load_target_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, _GOLDEN_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def _run_scanner(plugin_cls, config: dict, url: str, flow_id: str) -> list:
    from pwnproxy.plugins.core.base import PluginContext
    from pwnproxy.shared.models import Flow

    plugin = plugin_cls(context=PluginContext(config=config))
    await plugin.on_load()
    try:
        flow = Flow(
            id=flow_id,
            method="GET",
            url=url,
            request_headers={},
            request_body=None,
        )
        return [f async for f in plugin.on_flow(flow)]
    finally:
        await plugin.on_unload()


# ── SQLi golden targets ────────────────────────────────────────────────────


@pytest.mark.golden
class TestGoldenSqliTargets:
    @pytest.fixture(scope="class")
    def target(self):
        module = _load_target_module("golden_sqli_target", "sqli_target.py")
        t = module.SqliTargetServer()
        t.start()
        yield t
        t.stop()

    @pytest.mark.asyncio
    async def test_error_based_finding_on_error_endpoint(self, target):
        from pwnproxy.plugins.scanners.sqli.plugin import SQLiScannerPlugin

        findings = await _run_scanner(
            SQLiScannerPlugin,
            {"depth": "fast", "evasion_level": "none"},
            f"{target.base_url}/sqli/error?id=1",
            "golden-sqli-error",
        )
        assert any(
            f.technique == "error-based" and f.confidence == "confirmed"
            for f in findings
        ), f"no error-based finding: {[f.technique for f in findings]}"

    @pytest.mark.asyncio
    async def test_zero_findings_on_safe(self, target):
        from pwnproxy.plugins.scanners.sqli.plugin import SQLiScannerPlugin

        findings = await _run_scanner(
            SQLiScannerPlugin,
            {"depth": "standard", "evasion_level": "none"},
            f"{target.base_url}/sqli/safe?id=1",
            "golden-sqli-safe",
        )
        assert findings == [], f"false positives on /sqli/safe: {[f.technique for f in findings]}"

    @pytest.mark.asyncio
    async def test_zero_findings_on_noisy(self, target):
        from pwnproxy.plugins.scanners.sqli.plugin import SQLiScannerPlugin

        findings = await _run_scanner(
            SQLiScannerPlugin,
            {"depth": "standard", "evasion_level": "none"},
            f"{target.base_url}/sqli/noisy?id=1",
            "golden-sqli-noisy",
        )
        assert findings == [], f"false positives on /sqli/noisy: {[f.technique for f in findings]}"

    @pytest.mark.asyncio
    async def test_one_boolean_blind_finding_on_boolean_endpoint(self, target):
        from pwnproxy.plugins.scanners.sqli.plugin import SQLiScannerPlugin

        findings = await _run_scanner(
            SQLiScannerPlugin,
            {"depth": "standard", "evasion_level": "none"},
            f"{target.base_url}/sqli/boolean?id=1",
            "golden-sqli-boolean",
        )
        boolean_findings = [f for f in findings if f.technique == "boolean-blind"]
        assert len(boolean_findings) == 1, (
            f"expected exactly 1 boolean-blind finding, got {[f.technique for f in findings]}"
        )
        f = boolean_findings[0]
        assert f.param_name == "id"
        assert f.severity == "high"
        # 4-round stable differential → inferred (not raw content extraction).
        assert f.confidence == "inferred", f"boolean-blind should be inferred, got {f.confidence}"


# ── XSS golden targets ─────────────────────────────────────────────────────


@pytest.mark.golden
class TestGoldenXssTargets:
    @pytest.fixture(scope="class")
    def target(self):
        module = _load_target_module("golden_xss_target", "xss_target.py")
        t = module.XssTargetServer()
        t.start()
        yield t
        t.stop()

    @pytest.mark.asyncio
    async def test_xss_on_breakout_attr(self, target):
        from pwnproxy.plugins.scanners.xss.plugin import XSSScannerPlugin

        findings = await _run_scanner(
            XSSScannerPlugin,
            {"depth": "fast", "evasion_level": "none"},
            f"{target.base_url}/attr?name=hello",
            "golden-xss-attr",
        )
        assert any(
            f.technique == "reflected-xss" and f.param_name == "name"
            for f in findings
        ), f"no reflected-xss on /attr: {[f.technique for f in findings]}"

    @pytest.mark.asyncio
    async def test_no_reflected_xss_on_escaped_attr(self, target):
        from pwnproxy.plugins.scanners.xss.plugin import XSSScannerPlugin

        findings = await _run_scanner(
            XSSScannerPlugin,
            {"depth": "fast", "evasion_level": "none"},
            f"{target.base_url}/attr-safe?name=hello",
            "golden-xss-attr-safe",
        )
        assert "reflected-xss" not in [f.technique for f in findings], (
            f"false XSS on /attr-safe: {[f.technique for f in findings]}"
        )

    @pytest.mark.asyncio
    async def test_unescaped_reflection_is_not_xss(self, target):
        """Escaped-but-reflected input → unescaped-reflection low/tentative,
        never reflected-xss (task 6.4)."""
        from pwnproxy.plugins.scanners.xss.plugin import XSSScannerPlugin

        findings = await _run_scanner(
            XSSScannerPlugin,
            {"depth": "fast", "evasion_level": "none"},
            f"{target.base_url}/safe?name=hello",
            "golden-xss-safe",
        )
        assert "reflected-xss" not in [f.technique for f in findings]
        low = [f for f in findings if f.technique == "unescaped-reflection"]
        assert low, f"escaped reflection should emit unescaped-reflection, got {[f.technique for f in findings]}"
        assert low[0].severity == "low"
        assert low[0].confidence == "tentative"

    @pytest.mark.asyncio
    async def test_xss_on_js_and_comment_contexts(self, target):
        from pwnproxy.plugins.scanners.xss.plugin import XSSScannerPlugin

        for path in ("/js", "/comment"):
            findings = await _run_scanner(
                XSSScannerPlugin,
                {"depth": "fast", "evasion_level": "none"},
                f"{target.base_url}{path}?name=hello",
                f"golden-xss-{path.strip('/')}",
            )
            assert any(f.technique == "reflected-xss" for f in findings), (
                f"no reflected-xss on {path}: {[f.technique for f in findings]}"
            )
