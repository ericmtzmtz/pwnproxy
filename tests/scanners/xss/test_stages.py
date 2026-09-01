"""Regression tests for the XSS detection stages.

Covers the scanner-accuracy group 4 work:
- ReflectedStage uses the ContextAnalyzer + is_exploitable gate instead of the
  old ``_detect_context`` 50-char heuristic and ``point.original`` access.
- A reflected-but-not-exploitable canary yields ``unescaped-reflection``
  (low / tentative) and does NOT confirm the point.
- The old ``point.original`` bug is dead: the stage never reads an
  ``original`` attribute (InjectionPoint only has ``value``), so running it
  against a real InjectionPoint proves no regression.
"""

import asyncio

import httpx
import pytest

from pwnproxy.shared.scan.stages.xss_stages import (
    _default_canary,
    ContextAwareStage,
    ReflectedStage,
)
from pwnproxy.shared.models import Flow
from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.plugins.scanners.xss.payloads import get_payloads_for_context

CANARY = "pwnxss-testcanary123"
PROBE_HTML_BODY = f"<html><body><p>{CANARY}</p></body></html>"
PROBE_HTML_ATTR = f'<html><body><input value="{CANARY}"></body></html>'


class FakeXssReplayer:
    def __init__(self, probe_body=PROBE_HTML_BODY, exploitable=True):
        self.probe_body = probe_body
        self.exploitable = exploitable
        self.calls = []
        self.build_calls = []
        self.sent = None

    async def replay(self, point, payload, timeout=5.0, evasion_level="none"):
        self.calls.append(payload)
        self.sent = payload
        if payload == CANARY:
            return httpx.Response(200, text=self.probe_body)
        if self.exploitable:
            body = f"<html><body><p>{payload}</p></body></html>"
        else:
            escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
            body = f"<html><body><p>{escaped}</p></body></html>"
        return httpx.Response(200, text=body)

    def build_payload_request(self, point, payload, evasion_level="none"):
        self.build_calls.append(payload)
        return httpx.Request("GET", point.url)


def _point(value="1"):
    return InjectionPoint(
        name="q",
        value=value,
        location="query",
        flow_id="f1",
        method="GET",
        url="http://t.com/page?q=1",
        host="t.com",
        path="/page",
        original_headers={},
        original_body=None,
    )


def _flow():
    return Flow(id="f1", method="GET", url="http://t.com/page?q=1", request_headers={})


def _run(stage, points):
    return asyncio.run(stage.execute(_flow(), points))


class TestReflectedStagePointValueRegression:
    def test_point_value_used_not_original(self):
        """The stage must not access ``point.original`` (which does not exist).
        A real InjectionPoint has only ``value``; if the old bug returned the
        stage would raise AttributeError."""
        replayer = FakeXssReplayer(exploitable=True)
        stage = ReflectedStage(replayer, canary_provider=lambda: CANARY)
        result = _run(stage, [_point()])
        assert len(result.findings) >= 1
        xss = [f for f in result.findings if f.technique == "reflected-xss"]
        assert xss, result.findings
        assert replayer.sent is not None


class TestReflectedStageExploitabilityGate:
    def test_exploitable_confirms_reflected_xss(self):
        replayer = FakeXssReplayer(probe_body=PROBE_HTML_BODY, exploitable=True)
        stage = ReflectedStage(replayer, canary_provider=lambda: CANARY)
        result = _run(stage, [_point()])

        xss = [f for f in result.findings if f.technique == "reflected-xss"]
        assert len(xss) == 1
        f = xss[0]
        assert f.severity == "high"
        assert f.confidence == "confirmed"
        assert f.payload != CANARY
        html_body_payloads = get_payloads_for_context("html_body")
        assert f.payload in [p.value for p in html_body_payloads]
        assert f.extra and f.extra.get("context") == "html_body"
        assert len(result.confirmed_points) == 1

    def test_reflected_but_not_exploitable_is_unescaped_reflection(self):
        replayer = FakeXssReplayer(probe_body=PROBE_HTML_BODY, exploitable=False)
        stage = ReflectedStage(replayer, canary_provider=lambda: CANARY)
        result = _run(stage, [_point()])

        low = [f for f in result.findings if f.technique == "unescaped-reflection"]
        assert len(low) == 1
        f = low[0]
        assert f.severity == "low"
        assert f.confidence == "tentative"
        assert "reflected-xss" not in [x.technique for x in result.findings]
        assert result.confirmed_points == set()  # not exploitable → do not confirm

    def test_not_reflected_skips_point(self):
        replayer = FakeXssReplayer(probe_body="<html><body>nothing here</body></html>")
        stage = ReflectedStage(replayer, canary_provider=lambda: CANARY)
        result = _run(stage, [_point()])
        assert result.findings == []
        assert result.confirmed_points == set()

    def test_multiple_contexts_uses_first_exploitable(self):
        # Canary reflected in both html_body and html_attr; exploitable path taken.
        probe_body = f'<html><body><p>{CANARY}</p><input value="{CANARY}"></body></html>'
        replayer = FakeXssReplayer(probe_body=probe_body, exploitable=True)
        stage = ReflectedStage(replayer, canary_provider=lambda: CANARY)
        result = _run(stage, [_point()])
        xss = [f for f in result.findings if f.technique == "reflected-xss"]
        assert len(xss) == 1


class TestContextAwareStage:
    def test_deep_uses_exploitable_gate(self):
        replayer = FakeXssReplayer(probe_body=PROBE_HTML_BODY, exploitable=True)
        stage = ContextAwareStage(replayer, canary_provider=lambda: CANARY)
        result = _run(stage, [_point()])
        xss = [f for f in result.findings if f.technique == "reflected-xss"]
        assert xss
        assert xss[0].confidence == "confirmed"

    def test_deep_not_reflected_yields_nothing(self):
        replayer = FakeXssReplayer(probe_body="<html><body>none</body></html>")
        stage = ContextAwareStage(replayer, canary_provider=lambda: CANARY)
        result = _run(stage, [_point()])
        assert result.findings == []


@pytest.mark.asyncio
async def test_canary_is_unique_per_scan():
    """Per-scan unique canaries (no fixed constant)."""
    assert _default_canary() != _default_canary()
    assert _default_canary().startswith("pwnxss-")


class TestContextAwareStageDepthGating:
    """Task 4.7: depth=deep is what activates ContextAwareStage."""

    def test_context_aware_stage_only_runs_at_deep(self):
        from pwnproxy.plugins.core.chain import (
            DetectionChain,
            DetectionDepth,
            DetectionStage,
        )

        class DummyStage(DetectionStage):
            order = 99
            min_depth = DetectionDepth.FAST

            async def execute(self, flow, injection_points):
                from pwnproxy.plugins.core.chain import StageResult
                return StageResult(findings=[], confirmed_points=set())

        stages = [ContextAwareStage(FakeXssReplayer()), DummyStage()]
        chain_fast = DetectionChain(stages, DetectionDepth.FAST)
        chain_standard = DetectionChain(stages, DetectionDepth.STANDARD)
        chain_deep = DetectionChain(stages, DetectionDepth.DEEP)

        # should_run must be False below DEEP for ContextAwareStage
        assert not ContextAwareStage(FakeXssReplayer()).should_run(DetectionDepth.FAST)
        assert not ContextAwareStage(FakeXssReplayer()).should_run(DetectionDepth.STANDARD)
        assert ContextAwareStage(FakeXssReplayer()).should_run(DetectionDepth.DEEP)

