import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.plugins.scanners.lfi.replayer import LfiReplayer, METHODS


@pytest.mark.asyncio
async def test_replay_methods_iterates_all_methods():
    point = InjectionPoint(
        name="file", value="test", location="query",
        flow_id="f1", method="GET", url="http://target.com/page?file=test",
        host="target.com", path="/page",
        original_headers={"Host": "target.com"},
        original_body=None,
    )

    replayer = LfiReplayer()
    replayer._client = MagicMock()
    replayer._client.request = AsyncMock()
    replayer._client.request.return_value = MagicMock(status_code=200, text="root:x:0:0:")

    results = await replayer.replay_methods(point, "../../../../../../etc/passwd")

    assert len(results) == 5
    methods_tested = {m for m, _ in results}
    assert methods_tested == set(METHODS)


@pytest.mark.asyncio
async def test_replay_returns_none_on_timeout():
    point = InjectionPoint(
        name="q", value="test", location="query",
        flow_id="f1", method="GET", url="http://target.com/page?q=test",
        host="target.com", path="/page",
        original_headers={"Host": "target.com"},
        original_body=None,
    )

    replayer = LfiReplayer()
    replayer._client = MagicMock()
    from httpx import TimeoutException
    replayer._client.request = AsyncMock(side_effect=TimeoutException("timeout"))

    resp = await replayer.replay(point, "../../../../../../etc/passwd")
    assert resp is None
