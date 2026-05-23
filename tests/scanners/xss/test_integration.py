import pytest
from unittest.mock import AsyncMock, MagicMock

from pwnproxy.scanners.common.params import InjectionPoint
from pwnproxy.scanners.xss.canary import CanaryStore
from pwnproxy.scanners.xss.detector import ReflectedDetector, StoredDetector


def _make_resp(body: str) -> MagicMock:
    resp = MagicMock()
    resp.text = body
    resp.status_code = 200
    return resp


@pytest.mark.asyncio
async def test_reflected_detector_full_pipeline():
    point = InjectionPoint(
        name="q", value="test", location="query",
        flow_id="f1", method="GET", url="http://target.com/page?q=test",
        host="target.com", path="/page",
        original_headers={"Host": "target.com"},
        original_body=None,
    )

    replayer = MagicMock()
    replayer.replay = AsyncMock()

    probe_resp = _make_resp('<div>pwnxss-probe</div>')

    storage = MagicMock()
    storage.save_canary = AsyncMock()
    storage.mark_canary_found = AsyncMock()
    canary_store = CanaryStore(storage)

    detector = ReflectedDetector(replayer)

    canary_val = "pwnxss-abc12345"
    canary_store.generate = MagicMock(return_value=canary_val)
    canary_resp = _make_resp(f'<div>{canary_val}</div>')
    payload_resp = _make_resp('<div><script>alert(1)</script></div>')

    call_count = 0
    async def replay_side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return [probe_resp, canary_resp, payload_resp][min(call_count - 1, 2)]
    replayer.replay.side_effect = replay_side_effect

    finding = await detector.check(point, canary_store)

    assert finding is not None
    assert finding.xss_type == "reflected"
    assert finding.severity == "high"
    assert finding.confidence == "confirmed"
    assert finding.url == "http://target.com/page?q=test"
    assert finding.param_name == "q"
    assert finding.payload == "<script>alert(1)</script>"


@pytest.mark.asyncio
async def test_reflected_detector_no_reflection():
    point = InjectionPoint(
        name="q", value="test", location="query",
        flow_id="f1", method="GET", url="http://target.com/page?q=test",
        host="target.com", path="/page",
        original_headers={"Host": "target.com"},
        original_body=None,
    )

    replayer = MagicMock()
    replayer.replay = AsyncMock()
    replayer.replay.return_value = _make_resp('<div>not reflected</div>')

    storage = MagicMock()
    canary_store = CanaryStore(storage)

    detector = ReflectedDetector(replayer)
    finding = await detector.check(point, canary_store)

    assert finding is None


@pytest.mark.asyncio
async def test_stored_detector_full_pipeline():
    storage = MagicMock()
    storage.save_canary = AsyncMock()
    storage.mark_canary_found = AsyncMock()
    canary_store = CanaryStore(storage)

    canary = canary_store.generate()
    await canary_store.store(canary, "http://source.com/comment", "comment", "body")

    body = f"<div>{canary}</div>"
    detector = StoredDetector(canary_store)
    findings = await detector.check(body, "http://other.com/show")

    assert len(findings) == 1
    assert findings[0].xss_type == "stored"
    assert findings[0].severity == "critical"
    assert findings[0].reflection_url == "http://other.com/show"
    assert findings[0].url == "http://source.com/comment"


@pytest.mark.asyncio
async def test_reflected_detector_encoded_skip():
    point = InjectionPoint(
        name="q", value="test", location="query",
        flow_id="f1", method="GET", url="http://target.com/page?q=test",
        host="target.com", path="/page",
        original_headers={"Host": "target.com"},
        original_body=None,
    )

    replayer = MagicMock()
    replayer.replay = AsyncMock()

    probe_resp = _make_resp('<div>pwnxss-probe</div>')

    storage = MagicMock()
    storage.save_canary = AsyncMock()
    storage.mark_canary_found = AsyncMock()
    canary_store = CanaryStore(storage)

    detector = ReflectedDetector(replayer)

    canary_val = "pwnxss-abc12345"
    canary_store.generate = MagicMock(return_value=canary_val)
    canary_resp = _make_resp(f'<div>{canary_val}</div>')
    payload_resp = _make_resp('<div>&lt;script&gt;alert(1)&lt;/script&gt;</div>')

    call_count = 0
    async def replay_side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return [probe_resp, canary_resp, payload_resp][min(call_count - 1, 2)]
    replayer.replay.side_effect = replay_side_effect

    finding = await detector.check(point, canary_store)

    assert finding is None
