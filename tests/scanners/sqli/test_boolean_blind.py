import asyncio
import time

import httpx
import pytest

from pwnproxy.shared.scan.stages.sqli_stages import BooleanBlindStage
from pwnproxy.shared.models import Flow
from pwnproxy.shared.scan.params import InjectionPoint


TRUE_BODY = "<html><body><h1>Results</h1><p>order id=42</p></body></html>"
FALSE_BODY = "<html><body><h1>Error</h1><p>no rows found</p></body></html>"
SAME_BODY = "<html><body><h1>Same</h1><p>identical for both</p></body></html>"
UNSTABLE_FALSE_BODY = "<html><body><h1>Error</h1><p>transient glitch</p></body></html>"
CLEAN_BODY = "<html><body><h1>Home</h1><p>You are logged in.</p></body></html>"
UNSTABLE_CLEAN_BODY = "<html><body><h1>Home</h1><p>totally different page</p></body></html>"

CANONICAL_TRUE = "' OR 1=1-- "
CANONICAL_FALSE = "' OR 1=2-- "


def _point():
    return InjectionPoint(
        name="id",
        value="1",
        location="query",
        flow_id="f1",
        method="GET",
        url="http://t.com/page?id=1",
        host="t.com",
        path="/page",
        original_headers={},
        original_body=None,
    )


class FakeBooleanReplayer:
    def __init__(
        self,
        canonical_differentiable=True,
        escalation_differentiable=True,
        false_round2_different=False,
        unstable_baseline=False,
    ):
        self.canonical_differentiable = canonical_differentiable
        self.escalation_differentiable = escalation_differentiable
        self.false_round2_different = false_round2_different
        self.unstable_baseline = unstable_baseline
        self.calls = []
        self._false_count = 0
        self._clean_count = 0

    def _is_canonical(self, payload):
        return payload == CANONICAL_TRUE or payload == CANONICAL_FALSE

    @staticmethod
    def _is_true(payload):
        return "1=1" in payload

    async def replay(self, point, payload, timeout=5.0, evasion_level="none"):
        self.calls.append(payload)
        diff = self.canonical_differentiable if self._is_canonical(payload) else self.escalation_differentiable
        if self._is_true(payload):
            return httpx.Response(200, text=TRUE_BODY if diff else SAME_BODY)
        self._false_count += 1
        if self.false_round2_different and self._false_count >= 2:
            return httpx.Response(200, text=UNSTABLE_FALSE_BODY)
        return httpx.Response(200, text=FALSE_BODY if diff else SAME_BODY)

    async def send_clean(self, point, timeout=10.0):
        self._clean_count += 1
        if self.unstable_baseline and self._clean_count >= 2:
            return httpx.Response(200, text=UNSTABLE_CLEAN_BODY)
        return httpx.Response(200, text=CLEAN_BODY)

    def build_payload_request(self, point, payload, evasion_level="none"):
        return httpx.Request("GET", point.url)


def _run(replayer, deadline=None):
    stage = BooleanBlindStage(replayer, deadline=deadline)
    flow = Flow(id="f1", method="GET", url="http://t.com/page?id=1", request_headers={})
    return asyncio.run(stage.execute(flow, [_point()]))


def test_confirms_stable_4_rounds_inferred():
    result = _run(FakeBooleanReplayer())
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.technique == "boolean-blind"
    assert f.severity == "high"
    assert f.confidence == "inferred"
    assert _point().key in result.confirmed_points


def test_canonical_pair_only_when_differentiable():
    r = FakeBooleanReplayer()
    _run(r)
    # canonical pair replayed once per round (round1 + round2) = 2 calls each
    assert r.calls.count(CANONICAL_TRUE) == 2
    assert r.calls.count(CANONICAL_FALSE) == 2
    # no escalation pairs tested when canonical differentiates
    for esc_true in ["1 OR 1=1-- ", "') OR 1=1-- ", "' AND 1=1-- ", "' OR '1'='1'-- "]:
        assert esc_true not in r.calls


def test_rejects_inconsistent_false_false():
    result = _run(FakeBooleanReplayer(false_round2_different=True))
    assert len(result.findings) == 0
    assert result.confirmed_points == set()


def test_rejects_unstable_baseline_to_tentative():
    result = _run(FakeBooleanReplayer(unstable_baseline=True))
    assert len(result.findings) == 1
    assert result.findings[0].confidence == "tentative"


def test_canonical_not_differentiable_no_confirm():
    r = FakeBooleanReplayer(canonical_differentiable=False, escalation_differentiable=False)
    result = _run(r)
    assert len(result.findings) == 0
    assert result.confirmed_points == set()


def test_escalation_when_canonical_ambiguous():
    r = FakeBooleanReplayer(canonical_differentiable=False, escalation_differentiable=True)
    result = _run(r)
    assert len(result.findings) == 1
    # first escalation TRUE pair selected: "1 OR 1=1-- "
    assert result.findings[0].payload == "1 OR 1=1-- "


@pytest.mark.asyncio
async def test_stage_stops_at_deadline_without_error():
    r = FakeBooleanReplayer()
    stage = BooleanBlindStage(r, deadline=time.monotonic() - 1.0)
    flow = Flow(id="f1", method="GET", url="http://t.com/page?id=1", request_headers={})
    result = await stage.execute(flow, [_point()])
    assert len(result.findings) == 0
    assert r.calls == []


@pytest.mark.asyncio
async def test_no_deadline_preserves_behavior():
    r = FakeBooleanReplayer()
    stage = BooleanBlindStage(r)
    flow = Flow(id="f1", method="GET", url="http://t.com/page?id=1", request_headers={})
    result = await stage.execute(flow, [_point()])
    assert len(result.findings) == 1


@pytest.mark.asyncio
async def test_set_deadline_wires_intra_stage_cutoff():
    """BudgetChain calls set_deadline() before execute; the stage must honor it."""
    r = FakeBooleanReplayer()
    stage = BooleanBlindStage(r)
    stage.set_deadline(time.monotonic() - 1.0)
    flow = Flow(id="f1", method="GET", url="http://t.com/page?id=1", request_headers={})
    result = await stage.execute(flow, [_point()])
    assert len(result.findings) == 0
    assert r.calls == []
