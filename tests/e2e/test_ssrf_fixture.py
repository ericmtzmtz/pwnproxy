"""E2E validation of the SSRF scanner against a local vulnerable fixture.

Starts tests/fixtures/ssrf_target.py, runs the scan pipeline in-process,
and asserts the ssrf scanner produces a finding on a GET parameter.
"""

import asyncio
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT / "tests/fixtures"))

from ssrf_target import SsrfTargetServer  # noqa: E402

from apps.terminal.cli.scan import _scan_target  # noqa: E402


@pytest.fixture(scope="module")
def ssrf_server():
    server = SsrfTargetServer()
    server.start()
    yield server
    server.stop()


class TestFixture:
    def test_reflects_upstream_body(self, ssrf_server):
        import httpx

        server = SsrfTargetServer()
        server.start()
        try:
            # second fixture server as the "upstream" target
            resp = httpx.get(f"{ssrf_server.base_url}/fetch?url={server.base_url}/fetch?url=http://127.0.0.1:1/x")
            assert resp.status_code == 200
            assert "UPSTREAM_STATUS" in resp.text
        finally:
            server.stop()

    def test_refused_connection_is_200_with_error(self, ssrf_server):
        import httpx

        # nothing listens on this port -> connection refused
        resp = httpx.get(f"{ssrf_server.base_url}/fetch?url=http://127.0.0.1:1/x")
        assert resp.status_code == 200
        assert "UPSTREAM_ERROR" in resp.text

    def test_missing_url_param(self, ssrf_server):
        import httpx

        resp = httpx.get(f"{ssrf_server.base_url}/fetch")
        assert resp.status_code == 200
        assert "missing url param" in resp.text


class TestScanE2E:
    def test_scan_detects_ssrf(self, ssrf_server):
        from pwnproxy.plugins.core.loader import PluginLoader
        from pwnproxy.plugins.scanners.ssrf.plugin import SSRFScannerPlugin

        target = f"{ssrf_server.base_url}/fetch?url=http://127.0.0.1:18080/probe"

        async def run():
            # SSRF now confirms via OOB callback: start the callback server so
            # the fixture's server-side fetch of the injected URL produces a
            # canary hit.
            import pwnproxy.shared.http_server as http_mod
            if not http_mod._server or not http_mod._server.is_running:
                http_mod._server = http_mod.HTTPCallbackServer(host="127.0.0.1", port=0)
            server = await http_mod.get_server()
            if not server.is_running:
                await server.start()
            loader = PluginLoader()
            await loader.load_builtin(SSRFScannerPlugin())
            return await _scan_target(loader, target, timeout=30, method="GET")

        findings = asyncio.run(run())
        assert findings, "SSRF scanner produced no findings against the fixture"
        assert any(f.scanner == "ssrf" for f in findings), [
            (f.scanner, f.technique) for f in findings
        ]
        assert any(f.technique == "ssrf-oob" for f in findings), [
            (f.scanner, f.technique) for f in findings
        ]
