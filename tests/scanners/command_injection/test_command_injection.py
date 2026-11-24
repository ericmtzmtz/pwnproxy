"""Command-injection detection tests.

Two layers:

* ``TestStageBaseline`` / ``TestStageContentType`` drive
  ``CommandInjectionStage`` directly with a scripted replayer, so request
  counts and baselines are asserted exactly.
* ``TestGoldenCommandInjection`` runs the real plugin+loader against the
  in-process fixture in ``tests/golden/command_injection_target.py``.

The rule under test: a ``confirmed`` command-injection finding needs a *text*
response, a signature that is **not** in the baseline response, and a
signature specific enough to be command output.
"""

import contextlib
import importlib.util
from pathlib import Path

import pytest

from pwnproxy.plugins.scanners.command_injection.payloads import Payload
from pwnproxy.plugins.scanners.command_injection.signatures import (
    get_evidence,
    has_command_output,
)
from pwnproxy.shared.models import Flow
from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.shared.scan.stages.command_injection_stages import CommandInjectionStage

_GOLDEN_DIR = Path(__file__).resolve().parents[2] / "golden"

PAYLOADS = [
    Payload("; id", "command-injection"),
    Payload("; whoami", "command-injection"),
    Payload("; ls -la", "command-injection"),
]

# Same shape as the body that produced the live false positive: a PDF decoded
# as text has "endobj" / "stream" on their own lines.
PDF_BODY = (
    b"%PDF-1.4\n"
    b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    b"6 0 obj\n<< /ProcSet [/PDF /Text] >>\nendobj\n"
    b"stream\nendstream\ntrailer\nstartxref\n0\n%%EOF\n"
)
UID_OUTPUT = "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
PASSWD_OUTPUT = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin/nologin\n"
SAFE_TEXT = "<html><body><h1>Static page</h1></body></html>"


class _Resp:
    """Minimal httpx.Response stand-in (headers/content/text)."""

    def __init__(self, body: bytes, content_type: str = "text/plain", status_code: int = 200):
        self._body = body
        self._content_type = content_type
        self.status_code = status_code

    @property
    def content(self) -> bytes:
        return self._body

    @property
    def text(self) -> str:
        return self._body.decode("utf-8", "replace")

    @property
    def headers(self) -> dict:
        if not self._content_type:
            return {}
        return {"content-type": self._content_type}


class _ScriptedReplayer:
    """Replayer with a fixed clean response and a fixed payload response."""

    def __init__(self, clean: _Resp | None, payload: _Resp | None):
        self._clean = clean
        self._payload = payload
        self.clean_calls = 0
        self.payload_calls = 0

    async def send_clean(self, point, timeout=10.0):
        self.clean_calls += 1
        return self._clean

    async def replay(self, point, payload, timeout=5.0, evasion_level="none"):
        self.payload_calls += 1
        return self._payload


def _point() -> InjectionPoint:
    return InjectionPoint(
        name="cmd", value="1", location="query",
        flow_id="f1", method="GET", url="http://target.test/page?cmd=1",
        host="target.test", path="/page",
        original_headers={"Host": "target.test"}, original_body=None,
    )


def _flow(response_headers=None, response_body=None) -> Flow:
    return Flow(
        id="f1", method="GET", url="http://target.test/page?cmd=1",
        request_headers={"Host": "target.test"}, request_body=None,
        response_headers=response_headers, response_body=response_body,
    )


def _stage(replayer, detector=has_command_output) -> CommandInjectionStage:
    return CommandInjectionStage(replayer, PAYLOADS, detector, get_evidence)


class TestStageBaseline:
    """The signature must be new: output already present without a payload is page text."""

    @pytest.mark.asyncio
    async def test_uid_only_after_payload_confirms(self):
        replayer = _ScriptedReplayer(
            clean=_Resp(SAFE_TEXT.encode(), "text/html"),
            payload=_Resp(UID_OUTPUT.encode(), "text/plain"),
        )
        result = await _stage(replayer).execute(_flow(), [_point()])
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert (finding.scanner, finding.confidence, finding.payload) == (
            "command-injection", "confirmed", "; id",
        )
        assert finding.evidence.startswith("Command output detected (uid):")
        assert replayer.clean_calls == 1
        assert replayer.payload_calls == 1

    @pytest.mark.asyncio
    async def test_signature_already_in_baseline_is_not_a_finding(self):
        replayer = _ScriptedReplayer(
            clean=_Resp(UID_OUTPUT.encode(), "text/plain"),
            payload=_Resp(UID_OUTPUT.encode(), "text/plain"),
        )
        result = await _stage(replayer).execute(_flow(), [_point()])
        assert result.findings == []
        assert result.confirmed_points == set()
        # One baseline for the point, reused for every payload of that point.
        assert replayer.clean_calls == 1
        assert replayer.payload_calls == len(PAYLOADS)

    @pytest.mark.asyncio
    async def test_baseline_with_one_technique_does_not_hide_another(self):
        replayer = _ScriptedReplayer(
            clean=_Resp(UID_OUTPUT.encode(), "text/plain"),
            payload=_Resp(PASSWD_OUTPUT.encode(), "text/plain"),
        )
        result = await _stage(replayer).execute(_flow(), [_point()])
        assert len(result.findings) == 1
        assert result.findings[0].evidence.startswith("Command output detected (passwd):")

    @pytest.mark.asyncio
    async def test_captured_response_is_the_baseline_without_a_request(self):
        replayer = _ScriptedReplayer(
            clean=_Resp(b"never used", "text/plain"),
            payload=_Resp(UID_OUTPUT.encode(), "text/plain"),
        )
        flow = _flow(response_headers={"content-type": "text/plain"}, response_body=UID_OUTPUT.encode())
        result = await _stage(replayer).execute(flow, [_point()])
        assert result.findings == []
        assert replayer.clean_calls == 0
        assert replayer.payload_calls == len(PAYLOADS)

    @pytest.mark.asyncio
    async def test_one_baseline_per_point_reused_for_all_payloads(self):
        replayer = _ScriptedReplayer(
            clean=_Resp(SAFE_TEXT.encode(), "text/html"),
            payload=_Resp(SAFE_TEXT.encode(), "text/html"),
        )
        result = await _stage(replayer).execute(_flow(), [_point()])
        assert result.findings == []
        assert replayer.clean_calls == 1
        assert replayer.payload_calls == len(PAYLOADS)

    @pytest.mark.asyncio
    async def test_failed_baseline_skips_point_fail_closed(self):
        replayer = _ScriptedReplayer(clean=None, payload=_Resp(UID_OUTPUT.encode(), "text/plain"))
        result = await _stage(replayer).execute(_flow(), [_point()])
        assert result.findings == []
        assert replayer.clean_calls == 1
        assert replayer.payload_calls == 0

    @pytest.mark.asyncio
    async def test_stage_drops_finding_when_detector_ignores_baseline(self):
        """The stage, not just the plugin detector, enforces the baseline rule."""
        def sloppy_detector(body: str, baseline: str = "") -> tuple[bool, str]:
            return ("root" in body), "whoami"

        replayer = _ScriptedReplayer(
            clean=_Resp(b"Welcome back root!\n", "text/plain"),
            payload=_Resp(b"root\n", "text/plain"),
        )
        result = await _stage(replayer, sloppy_detector).execute(_flow(), [_point()])
        assert result.findings == []
        assert replayer.payload_calls == len(PAYLOADS)


class TestStageContentType:
    """Binary responses are skipped before any payload is sent."""

    @pytest.mark.asyncio
    async def test_captured_pdf_skips_without_any_request(self):
        replayer = _ScriptedReplayer(
            clean=_Resp(PDF_BODY, "application/pdf"),
            payload=_Resp(PDF_BODY, "application/pdf"),
        )
        flow = _flow(response_headers={"content-type": "application/pdf"}, response_body=PDF_BODY)
        result = await _stage(replayer).execute(flow, [_point()])
        assert result.findings == []
        assert replayer.clean_calls == 0
        assert replayer.payload_calls == 0

    @pytest.mark.asyncio
    async def test_captured_image_skips_without_any_request(self):
        png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 32
        replayer = _ScriptedReplayer(clean=_Resp(png, "image/png"), payload=_Resp(png, "image/png"))
        flow = _flow(response_headers={"content-type": "image/png"}, response_body=png)
        result = await _stage(replayer).execute(flow, [_point()])
        assert result.findings == []
        assert replayer.clean_calls == 0
        assert replayer.payload_calls == 0

    @pytest.mark.asyncio
    async def test_binary_clean_baseline_skips_payloads(self):
        replayer = _ScriptedReplayer(
            clean=_Resp(PDF_BODY, "application/pdf"),
            payload=_Resp(PDF_BODY, "application/pdf"),
        )
        result = await _stage(replayer).execute(_flow(), [_point()])
        assert result.findings == []
        assert replayer.clean_calls == 1
        assert replayer.payload_calls == 0

    @pytest.mark.asyncio
    async def test_binary_payload_response_is_not_a_finding(self):
        replayer = _ScriptedReplayer(
            clean=_Resp(SAFE_TEXT.encode(), "text/html"),
            payload=_Resp(UID_OUTPUT.encode(), "image/png"),
        )
        result = await _stage(replayer).execute(_flow(), [_point()])
        assert result.findings == []

    @pytest.mark.asyncio
    async def test_missing_content_type_decodable_as_text_confirms(self):
        replayer = _ScriptedReplayer(
            clean=_Resp(b"nothing here\n", ""),
            payload=_Resp(UID_OUTPUT.encode(), ""),
        )
        flow = _flow(response_headers={"content-type": ""}, response_body=b"nothing here\n")
        result = await _stage(replayer).execute(flow, [_point()])
        assert len(result.findings) == 1
        assert result.findings[0].confidence == "confirmed"


def _load_target_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, _GOLDEN_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def _run(url: str, flow_id: str, flow: Flow | None = None) -> list:
    from pwnproxy.plugins.core.loader import PluginLoader
    from pwnproxy.plugins.scanners.command_injection.plugin import (
        CommandInjectionScannerPlugin,
    )

    loader = PluginLoader()
    plugin = CommandInjectionScannerPlugin()
    await loader.load_builtin(plugin, config={"depth": "fast", "evasion_level": "none"})
    try:
        if flow is None:
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

    @pytest.mark.asyncio
    async def test_zero_findings_on_pdf(self, target):
        findings = await _run(f"{target.base_url}/pdf?cmd=1", "golden-cmd-pdf")
        assert [f for f in findings if f.scanner == "command-injection"] == [], (
            f"false positive on /pdf: {[(f.scanner, f.evidence) for f in findings]}"
        )

    @pytest.mark.asyncio
    async def test_zero_findings_when_output_is_already_in_baseline(self, target):
        findings = await _run(f"{target.base_url}/preexisting?cmd=1", "golden-cmd-preexisting")
        assert [f for f in findings if f.scanner == "command-injection"] == [], (
            f"pre-existing output reported as injection: {[(f.scanner, f.evidence) for f in findings]}"
        )

    @pytest.mark.asyncio
    async def test_captured_pdf_flow_is_skipped_without_requests(self, target):
        """End-to-end: the response captured by the proxy reaches the stage."""
        before = target.request_count
        url = f"{target.base_url}/pdf?cmd=1"
        flow = Flow(
            id="golden-cmd-pdf-captured",
            method="GET",
            url=url,
            request_headers={},
            request_body=None,
            status_code=200,
            response_headers={"content-type": "application/pdf"},
            response_body=target.pdf_body,
        )
        findings = await _run(url, flow.id, flow)
        assert [f for f in findings if f.scanner == "command-injection"] == []
        assert target.request_count == before, "binary captured flow must not be replayed"
