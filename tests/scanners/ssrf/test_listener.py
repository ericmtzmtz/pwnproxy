import pytest

from pwnproxy.services.scanners.ssrf.listener import CallbackServer


@pytest.mark.asyncio
async def test_generate_payload_format():
    server = CallbackServer(host="127.0.0.1", port=9999)
    payload = server.generate_payload(canary="test-canary-123")
    assert "127.0.0.1:9999" in payload
    assert "test-canary-123" in payload


@pytest.mark.asyncio
async def test_generate_payload_random_canary():
    server = CallbackServer(host="0.0.0.0", port=8080)
    payload = server.generate_payload()
    assert len(payload.split("/")[-1]) == 36  # UUID length


@pytest.mark.asyncio
async def test_pop_hit():
    server = CallbackServer()
    server._hits["abc"] = {"canary": "abc", "remote_ip": "1.2.3.4"}
    hit = server.pop_hit("abc")
    assert hit is not None
    assert hit["canary"] == "abc"
    assert server.pop_hit("abc") is None


@pytest.mark.asyncio
async def test_pop_hit_unknown():
    server = CallbackServer()
    assert server.pop_hit("nonexistent") is None
