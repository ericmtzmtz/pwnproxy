"""Tests for DomStage (static DOM XSS detection)."""
from unittest.mock import MagicMock

import pytest

from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.shared.scan.stages.xss_stages import DomStage

CANARY = "pwnxss-domtest"


class FakeReplayer:
    def __init__(self, html: str):
        self._html = html
        self.sent = []

    async def replay(self, point, payload, timeout=5.0, evasion_level="none"):
        self.sent.append(payload)
        resp = MagicMock()
        resp.text = self._html
        resp.headers = {}
        return resp

    def build_payload_request(self, point, payload, evasion_level="none"):
        return MagicMock()


def _point(name="default", location="query") -> InjectionPoint:
    return InjectionPoint(
        name=name, value="English", location=location,
        flow_id="f1", method="GET", url="http://target.com/xss_d/?default=English",
        host="target.com", path="/xss_d/",
        original_headers={"Host": "target.com"}, original_body=None,
    )


def _flow():
    from pwnproxy.shared.models import Flow
    return Flow(id="f1", method="GET", url="http://target.com/xss_d/?default=English", request_headers={"Host": "target.com"})


def _stage(html: str) -> DomStage:
    return DomStage(FakeReplayer(html), canary_provider=lambda: CANARY)


@pytest.mark.asyncio
async def test_document_write_sink_emits_dom_xss():
    # DVWA xss_d style: the reflected value lands directly in document.write
    html = (
        "<html><body><select><option value='English'>English</option></select>"
        "<script>var lang = 'pwnxss-domtest';"
        "document.write(\"<option value='\" + 'pwnxss-domtest' + \"'>\" + lang + \"</option>\");</script></body></html>"
    )
    result = await _stage(html).execute(_flow(), [_point()])
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.technique == "dom-xss"
    assert f.confidence == "inferred"
    assert f.severity == "medium"
    assert f.extra["dom_sink"] == "document.write"


@pytest.mark.asyncio
async def test_inner_html_sink():
    html = "<script>el.innerHTML = 'pwnxss-domtest';</script>"
    result = await _stage(html).execute(_flow(), [_point()])
    assert len(result.findings) == 1
    assert result.findings[0].extra["dom_sink"] == "innerHTML"


@pytest.mark.asyncio
async def test_location_and_eval_sinks():
    for script, sink_name in [
        ("location.href = 'pwnxss-domtest';", "location.href"),
        ("eval('pwnxss-domtest');", "eval"),
        ("setTimeout('pwnxss-domtest', 100);", "setTimeout"),
    ]:
        result = await _stage(f"<script>{script}</script>").execute(_flow(), [_point()])
        assert len(result.findings) == 1, script
        assert result.findings[0].extra["dom_sink"] == sink_name, script


@pytest.mark.asyncio
async def test_canary_in_script_without_sink_no_finding():
    html = "<script>var x = 'pwnxss-domtest'; console.log(x);</script>"
    result = await _stage(html).execute(_flow(), [_point()])
    assert result.findings == []


@pytest.mark.asyncio
async def test_canary_in_html_body_no_dom_finding():
    # canary reflected server-side in HTML body (ReflectedStage owns it)
    html = "<html><body><div>pwnxss-domtest</div><script>document.write('x');</script></body></html>"
    result = await _stage(html).execute(_flow(), [_point()])
    assert result.findings == []


@pytest.mark.asyncio
async def test_canary_not_reflected_at_all_skips():
    html = "<html><body><script>document.write('other');</script></body></html>"
    result = await _stage(html).execute(_flow(), [_point()])
    assert result.findings == []


@pytest.mark.asyncio
async def test_param_reads_location_into_sink_emits_dom_xss():
    # DVWA xss_d pattern: server does NOT reflect the canary; the script
    # reads the param name from location.href and writes to document.write.
    html = (
        "<html><body><select name='default'>"
        "<script>"
        "if (document.location.href.indexOf('default=') >= 0) {"
        "var lang = document.location.href.substring("
        "document.location.href.indexOf('default=')+8);"
        "document.write(\"<option value='\" + lang + \"'>\" + lang + \"</option>\");}"
        "</script></select></body></html>"
    )
    result = await _stage(html).execute(_flow(), [_point("default")])
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.technique == "dom-xss"
    assert f.confidence == "inferred"
    assert f.extra["dom_sink"] == "document.write"
    assert "default" in f.evidence


@pytest.mark.asyncio
async def test_urlsearchparams_read_emits_dom_xss():
    html = (
        "<script>"
        "var q = new URLSearchParams(location.search).get('q');"
        "el.innerHTML = q;"
        "</script>"
    )
    result = await _stage(html).execute(_flow(), [_point("q")])
    assert len(result.findings) == 1
    assert result.findings[0].extra["dom_sink"] == "innerHTML"


@pytest.mark.asyncio
async def test_param_read_without_sink_no_finding():
    html = "<script>var lang = location.href.indexOf('default=');</script>"
    result = await _stage(html).execute(_flow(), [_point("default")])
    assert result.findings == []


def test_dom_stage_runs_at_fast_depth():
    from pwnproxy.plugins.core.chain import DetectionDepth
    assert DomStage.min_depth == DetectionDepth.FAST
