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
async def test_publish_does_not_block_slow_consumer(bus):
    """A slow consumer must not stall the producer: publish() is non-blocking."""
    slow_topic = "crawl.progress"  # IMPORTANT in TOPIC_QOS
    received = []

    async def slow_collect():
        async for e in bus.subscribe(slow_topic):
            received.append(e.data)
            await asyncio.sleep(0.01)

    task = asyncio.create_task(slow_collect())
    await asyncio.sleep(0.05)

    # Publishing many events rapidly must return quickly (no await on full queue).
    import time
    start = time.monotonic()
    for i in range(30):
        await bus.publish(slow_topic, {"job_id": "j1", "pct": i})
    elapsed = time.monotonic() - start
    assert elapsed < 2.0, f"publish blocked too long: {elapsed:.2f}s"

    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    # The slow consumer may not have drained everything, but publish succeeded.
    assert len(received) <= 30


@pytest.mark.asyncio
async def test_best_effort_topic_drops_under_pressure_without_blocking(bus):
    """A BEST_EFFORT topic with a consumer that never drains drops incoming
    events instead of growing the queue or blocking the producer."""
    topic = "crawler.url"  # BEST_EFFORT in TOPIC_QOS

    async def never_drains():
        async for _e in bus.subscribe(topic):
            await asyncio.sleep(10)

    task = asyncio.create_task(never_drains())
    await asyncio.sleep(0.05)

    # The subscriber's queue has BEST_EFFORT capacity (64); flood well past it.
    queues = bus._subscribers.get(topic, [])
    assert queues, "subscriber queue should exist"
    capacity = queues[0]._maxsize

    for i in range(capacity * 3):
        await bus.publish(topic, {"url": f"http://x/{i}"})
        await asyncio.sleep(0)

    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    # BEST_EFFORT dropped most of the flood rather than blocking/growing.
    assert queues[0].dropped > 0


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

    # Poll instead of fixed sleep — consumer needs event loop time
    for _ in range(20):
        await asyncio.sleep(0.1)
        if received:
            break

    await client.stop()
    await server.stop()

    assert len(received) == 1, f"Expected 1, got {len(received)}"
    assert received[0] == ("proxy.flow", {"id": "test-1"})
