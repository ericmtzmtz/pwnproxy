import asyncio
import pytest

from pwnproxy.shared.bus import MessageBus, Envelope
from pwnproxy.shared.bus.transports.inprocess import InProcessBus


@pytest.fixture
def bus():
    return InProcessBus()


@pytest.mark.asyncio
async def test_envelope_has_all_fields():
    """Envelope should have topic, data, source, id, timestamp."""
    e = Envelope(topic="test", data={"hello": "world"}, source="pytest")
    assert e.topic == "test"
    assert e.data == {"hello": "world"}
    assert e.source == "pytest"
    assert e.id != ""
    assert e.timestamp is not None


@pytest.mark.asyncio
async def test_multiple_subscribers_receive_independently(bus):
    """Multiple subscribers on same topic each receive every message."""
    results_a = []
    results_b = []

    async def collect_a():
        async for e in bus.subscribe("test"):
            results_a.append(e.data)

    async def collect_b():
        async for e in bus.subscribe("test"):
            results_b.append(e.data)

    task_a = asyncio.create_task(collect_a())
    task_b = asyncio.create_task(collect_b())
    await asyncio.sleep(0.05)

    await bus.publish("test", "msg1")
    await asyncio.sleep(0.05)
    await bus.publish("test", "msg2")
    await asyncio.sleep(0.05)

    task_a.cancel()
    task_b.cancel()

    assert results_a == ["msg1", "msg2"], f"Got {results_a}"
    assert results_b == ["msg1", "msg2"], f"Got {results_b}"


@pytest.mark.asyncio
async def test_topic_isolation(bus):
    """Messages on topic A should not reach subscribers of topic B."""
    received_a = []
    received_b = []

    async def collect_a():
        async for e in bus.subscribe("topic_a"):
            received_a.append(e.data)

    async def collect_b():
        async for e in bus.subscribe("topic_b"):
            received_b.append(e.data)

    task_a = asyncio.create_task(collect_a())
    task_b = asyncio.create_task(collect_b())
    await asyncio.sleep(0.05)

    await bus.publish("topic_a", "only_a")
    await asyncio.sleep(0.05)

    task_a.cancel()
    task_b.cancel()

    assert received_a == ["only_a"]
    assert received_b == []  # topic_b subscriber should NOT receive topic_a messages


@pytest.mark.asyncio
async def test_subscriber_count(bus):
    """subscriber_count should reflect active subscribers."""
    assert bus.subscriber_count("test") == 0

    async def _():
        async for _ in bus.subscribe("test"):
            pass

    t = asyncio.create_task(_())
    await asyncio.sleep(0.05)
    assert bus.subscriber_count("test") == 1
    t.cancel()


@pytest.mark.asyncio
async def test_envelope_json_roundtrip():
    """Envelope.to_json() and Envelope.from_json() should roundtrip."""
    e1 = Envelope(topic="test", data=[1, 2, 3], source="pytest")
    raw = e1.to_json()
    e2 = Envelope.from_json(raw)
    assert e2.topic == e1.topic
    assert e2.data == e1.data
    assert e2.source == e1.source


@pytest.mark.asyncio
async def test_tcp_bridge_send_receive():
    """TcpBridgeServer should deliver messages to TcpBridgeClient."""
    from pwnproxy.shared.bus.transports.tcp_bridge import TcpBridgeServer, TcpBridgeClient

    received = []

    def on_event(topic, data):
        received.append((topic, data))

    server = TcpBridgeServer()
    port = await server.start()

    client = TcpBridgeClient(host="127.0.0.1", port=port, on_event=on_event)
    await client.start()
    await asyncio.sleep(0.3)

    await server.publish("proxy.flow", {"id": "test-1"})
    await asyncio.sleep(0.3)

    await client.stop()
    await server.stop()

    assert len(received) == 1, f"Expected 1, got {len(received)}"
    assert received[0] == ("proxy.flow", {"id": "test-1"})
