import pytest
from unittest.mock import AsyncMock, MagicMock

from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.plugins.scanners.xxe.replayer import XxeReplayer


@pytest.mark.asyncio
async def test_replay_xml_sends_correct_content_type():
    point = InjectionPoint(
        name="q", value="test", location="query",
        flow_id="f1", method="POST",
        url="http://target.com/api",
        host="target.com", path="/api",
        original_headers={"Host": "target.com", "content-type": "application/json"},
        original_body='{"user": "admin"}',
    )

    replayer = XxeReplayer()
    replayer._client = MagicMock()
    resp = MagicMock(status_code=200, text="ok")
    replayer._client.request = AsyncMock(return_value=resp)

    result = await replayer.replay_xml(point, "<root>test</root>")
    assert result is not None

    call_kwargs = replayer._client.request.call_args.kwargs
    assert call_kwargs["headers"]["content-type"] == "application/xml"


@pytest.mark.asyncio
async def test_replay_json_mutated_converts_body():
    point = InjectionPoint(
        name="user", value="admin", location="body",
        flow_id="f1", method="POST",
        url="http://target.com/api",
        host="target.com", path="/api",
        original_headers={"Host": "target.com", "content-type": "application/json"},
        original_body='{"user": "admin"}',
    )

    replayer = XxeReplayer()
    replayer._client = MagicMock()
    resp = MagicMock(status_code=200, text="ok")
    replayer._client.request = AsyncMock(return_value=resp)

    result = await replayer.replay_json_mutated(
        point, '<!ENTITY xxe SYSTEM "file:///etc/passwd">'
    )
    assert result is not None

    call_kwargs = replayer._client.request.call_args.kwargs
    content = call_kwargs["content"].decode()
    assert "file:///etc/passwd" in content
    assert "<user>" in content


@pytest.mark.asyncio
async def test_replay_raw_body_sends_content():
    point = InjectionPoint(
        name="q", value="test", location="query",
        flow_id="f1", method="POST",
        url="http://target.com/api",
        host="target.com", path="/api",
        original_headers={"Host": "target.com"},
        original_body=None,
    )

    replayer = XxeReplayer()
    replayer._client = MagicMock()
    resp = MagicMock(status_code=200, text="root:x:0:0:")
    replayer._client.request = AsyncMock(return_value=resp)

    result = await replayer.replay_raw_body(
        point, '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
    )
    assert result is not None

    call_kwargs = replayer._client.request.call_args.kwargs
    assert b"file:///etc/passwd" in call_kwargs["content"]


@pytest.mark.asyncio
async def test_replay_returns_none_on_timeout():
    point = InjectionPoint(
        name="q", value="test", location="query",
        flow_id="f1", method="GET", url="http://target.com/api",
        host="target.com", path="/api",
        original_headers={"Host": "target.com"},
        original_body=None,
    )

    replayer = XxeReplayer()
    replayer._client = MagicMock()
    from httpx import TimeoutException
    replayer._client.request = AsyncMock(side_effect=TimeoutException("timeout"))

    result = await replayer.replay_xml(point, "<root>test</root>")
    assert result is None
