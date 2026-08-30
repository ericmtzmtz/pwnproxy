"""Tests for event bus QoS: envelope classification, queue policies, metrics."""

import asyncio
import json
import pytest
from pwnproxy.shared.bus import Envelope
from pwnproxy.shared.bus.qos import QoSClassifiedQueue, _coalesce_key
from pwnproxy.shared.bus.topics import (
    QoSClass, TOPIC_QOS, FINDING_CREATED, CRAWL_PROGRESS,
    CRAWLER_FLOW, CRAWLER_URL, SCOPE_UPDATED,
)
from pwnproxy.shared.bus.transports.tcp_bridge import TcpBridgeServer, TcpBridgeClient


# ── Envelope QoS classification ─────────────────────────────────────

class TestEnvelopeQoS:
    def test_finding_created_is_critical(self):
        e = Envelope(topic=FINDING_CREATED, data={"id": "f1"})
        assert e.qos_class == QoSClass.CRITICAL

    def test_crawl_progress_is_important(self):
        e = Envelope(topic=CRAWL_PROGRESS, data={"job_id": "j1"})
        assert e.qos_class == QoSClass.IMPORTANT

    def test_crawler_flow_is_best_effort(self):
        e = Envelope(topic=CRAWLER_FLOW, data={"url": "http://x"})
        assert e.qos_class == QoSClass.BEST_EFFORT

    def test_scope_updated_is_critical(self):
        e = Envelope(topic=SCOPE_UPDATED, data={})
        assert e.qos_class == QoSClass.CRITICAL

    def test_unknown_topic_defaults_to_best_effort(self):
        e = Envelope(topic="some.random.topic", data={})
        assert e.qos_class == QoSClass.BEST_EFFORT

    def test_explicit_qos_overrides_topic_default(self):
        e = Envelope(topic=CRAWLER_FLOW, data={}, qos_class=QoSClass.CRITICAL)
        assert e.qos_class == QoSClass.CRITICAL

    def test_json_roundtrip_preserves_qos(self):
        e1 = Envelope(topic=FINDING_CREATED, data={"x": 1})
        raw = e1.to_json()
        e2 = Envelope.from_json(raw)
        assert e2.qos_class == QoSClass.CRITICAL
        assert e2.topic == FINDING_CREATED

    def test_from_json_backwards_compat_no_qos_field(self):
        """Envelope without qos_class in JSON defaults to BEST_EFFORT."""
        raw = json.dumps({"topic": "test", "data": {}, "source": "", "id": "x", "timestamp": "2026-01-01T00:00:00"})
        e = Envelope.from_json(raw)
        assert e.qos_class == QoSClass.BEST_EFFORT

    def test_from_json_invalid_qos_defaults(self):
        raw = json.dumps({"topic": "test", "data": {}, "source": "", "id": "x", "timestamp": "2026-01-01T00:00:00", "qos_class": "bogus"})
        e = Envelope.from_json(raw)
        assert e.qos_class == QoSClass.BEST_EFFORT


# ── Coalesce key ─────────────────────────────────────────────────────

class TestCoalesceKey:
    def test_progress_key(self):
        assert _coalesce_key("crawl.progress", {"job_id": "j1"}) == "progress:j1"
        assert _coalesce_key("bruteforce.progress", {"job_id": "j2"}) == "progress:j2"

    def test_triage_key(self):
        assert _coalesce_key("triage.updated", {"finding_id": "f1"}) == "triage:f1"
        assert _coalesce_key("triage.updated", {"id": "f2"}) == "triage:f2"

    def test_non_coalesceable(self):
        assert _coalesce_key("finding.created", {"id": "f1"}) is None
        assert _coalesce_key("crawl.started", {"job_id": "j1"}) is None


# ── QoSClassifiedQueue policies ─────────────────────────────────────

class TestQoSClassifiedQueue:
    def test_best_effort_drops_on_full(self):
        q = QoSClassifiedQueue(QoSClass.BEST_EFFORT, maxsize=2)
        assert q.put_nowait("t", {"n": 1}) is True
        assert q.put_nowait("t", {"n": 2}) is True
        assert q.put_nowait("t", {"n": 3}) is False  # dropped
        assert q.dropped == 1
        assert q.qsize == 2

    def test_important_coalesce_by_key(self):
        q = QoSClassifiedQueue(QoSClass.IMPORTANT, maxsize=10)
        q.put_nowait(CRAWL_PROGRESS, {"job_id": "j1", "fetched": 10})
        q.put_nowait(CRAWL_PROGRESS, {"job_id": "j1", "fetched": 20})
        q.put_nowait(CRAWL_PROGRESS, {"job_id": "j1", "fetched": 30})
        assert q.qsize == 1  # coalesced into one
        assert q.coalesced == 2
        topic, data = q._queue._queue[0]
        assert data["fetched"] == 30  # latest value

    def test_important_different_keys_coexist(self):
        q = QoSClassifiedQueue(QoSClass.IMPORTANT, maxsize=10)
        q.put_nowait(CRAWL_PROGRESS, {"job_id": "j1", "fetched": 10})
        q.put_nowait(CRAWL_PROGRESS, {"job_id": "j2", "fetched": 5})
        assert q.qsize == 2

    def test_important_non_coalesceable_direct_enqueue(self):
        q = QoSClassifiedQueue(QoSClass.IMPORTANT, maxsize=10)
        q.put_nowait(FINDING_CREATED, {"id": "f1"})
        q.put_nowait(FINDING_CREATED, {"id": "f2"})
        assert q.qsize == 2  # no key to coalesce on

    def test_critical_enqueues_when_not_full(self):
        q = QoSClassifiedQueue(QoSClass.CRITICAL, maxsize=10)
        assert q.put_nowait(FINDING_CREATED, {"id": "f1"}) is True
        assert q.qsize == 1

    def test_critical_retries_in_buffer_when_full(self):
        q = QoSClassifiedQueue(QoSClass.CRITICAL, maxsize=2)
        q.put_nowait(FINDING_CREATED, {"id": "f1"})
        q.put_nowait(FINDING_CREATED, {"id": "f2"})
        # Queue full — should go to retry buffer, not raise/drop
        result = q.put_nowait(FINDING_CREATED, {"id": "f3"})
        assert result is True  # producer never sees failure
        assert len(q._retry_buffer) == 1
        assert q.qsize == 2

    def test_coalesce_replaces_existing_key_in_queue(self):
        q = QoSClassifiedQueue(QoSClass.IMPORTANT, maxsize=10)
        q.put_nowait(CRAWL_PROGRESS, {"job_id": "j1", "fetched": 5})
        q.put_nowait(CRAWL_PROGRESS, {"job_id": "j2", "fetched": 10})
        q.put_nowait(CRAWL_PROGRESS, {"job_id": "j1", "fetched": 15})
        assert q.qsize == 2
        items = list(q._queue._queue)
        j1_item = next(d for t, d in items if d.get("job_id") == "j1")
        assert j1_item["fetched"] == 15


# ── TcpBridge QoS integration ───────────────────────────────────────

@pytest.mark.asyncio
async def test_tcp_bridge_finding_created_always_delivered():
    """FindingCreated (CRITICAL) is delivered even under BEST_EFFORT pressure."""
    received = []

    def on_event(topic, data):
        received.append((topic, data))

    server = TcpBridgeServer()
    port = await server.start()
    client = TcpBridgeClient(host="127.0.0.1", port=port, on_event=on_event)
    await client.start()
    await asyncio.sleep(0.3)

    # Flood with BEST_EFFORT events (small queue =64, but consumer is slow)
    for i in range(80):
        await server.publish(CRAWLER_FLOW, {"url": f"http://slow/{i}"})
    # Then send CRITICAL
    await server.publish(FINDING_CREATED, {"id": "f1"})
    await asyncio.sleep(1.0)

    await client.stop()
    await server.stop()

    finding_received = [t for t, d in received if t == FINDING_CREATED]
    assert len(finding_received) == 1, f"FindingCreated was lost! received={received[-5:]}"


@pytest.mark.asyncio
async def test_tcp_bridge_coalesce_progress():
    """Multiple crawl.progress for same job_id coalesce to latest."""
    received = []

    def on_event(topic, data):
        received.append((topic, data))

    server = TcpBridgeServer()
    port = await server.start()
    client = TcpBridgeClient(host="127.0.0.1", port=port, on_event=on_event)
    await client.start()
    await asyncio.sleep(0.3)

    for fetched in [1, 5, 10, 20, 50]:
        await server.publish(CRAWL_PROGRESS, {"job_id": "j1", "fetched": fetched})
    await asyncio.sleep(0.5)

    await client.stop()
    await server.stop()

    progress_events = [d for t, d in received if t == CRAWL_PROGRESS]
    # Should have at most 1 progress event (coalesced) — could be 0 if consumer
    # hasn't drained yet, or 1 if coalesced. Never 5.
    assert len(progress_events) <= 1, f"Expected coalesced progress, got {len(progress_events)}: {progress_events}"


@pytest.mark.asyncio
async def test_tcp_bridge_producer_never_blocks():
    """publish() returns immediately even when consumer is slow."""
    from pwnproxy.shared.bus.topics import CRAWLER_URL

    server = TcpBridgeServer()
    port = await server.start()
    # Connect but DON'T consume — consumer task will buffer
    reader_writer = await asyncio.wait_for(
        asyncio.open_connection("127.0.0.1", port), timeout=5
    )
    # Don't start TcpBridgeClient — no consumer draining
    await asyncio.sleep(0.2)

    import time
    start = time.monotonic()
    for i in range(200):
        await server.publish(CRAWLER_URL, {"url": f"http://x/{i}"})
    elapsed = time.monotonic() - start

    reader_writer[1].close()
    await server.stop()
    # publish should return in < 1 second total (non-blocking)
    assert elapsed < 1.0, f"publish() blocked for {elapsed:.2f}s"


@pytest.mark.asyncio
async def test_tcp_bridge_best_effort_drops_under_pressure():
    """BEST_EFFORT events are dropped when queue is full."""
    from pwnproxy.shared.bus.topics import CRAWLER_FLOW

    server = TcpBridgeServer()
    port = await server.start()
    # Connect but don't consume — queues fill up
    rw = await asyncio.wait_for(
        asyncio.open_connection("127.0.0.1", port), timeout=5
    )
    await asyncio.sleep(0.3)

    # Access the client queues to check dropped count
    writer = rw[1]
    async with server._lock:
        cq = server._client_queues.get(writer)

    # Flood to fill BEST_EFFORT queue (maxsize=64)
    for i in range(100):
        await server.publish(CRAWLER_FLOW, {"url": f"http://x/{i}"})

    if cq:
        assert cq.best_effort.dropped > 0, "BEST_EFFORT should have dropped events"

    writer.close()
    await server.stop()


@pytest.mark.asyncio
async def test_tcp_bridge_aging_prevents_important_starvation():
    """IMPORTANT events are served even under sustained CRITICAL traffic.

    Without aging, strict priority would starve IMPORTANT indefinitely.
    With aging (_STARVATION_LIMIT=4), IMPORTANT is forced-served after
    4 consecutive cycles where both CRITICAL and IMPORTANT are ready.
    """
    from pwnproxy.shared.bus.topics import CRAWL_PROGRESS
    received = []

    def on_event(topic, data):
        received.append((topic, data))

    server = TcpBridgeServer()
    port = await server.start()
    client = TcpBridgeClient(host="127.0.0.1", port=port, on_event=on_event)
    await client.start()
    await asyncio.sleep(0.3)

    # Publish CRITICAL and IMPORTANT in the same burst so both queues have
    # data simultaneously when the consumer runs its next cycle.
    for i in range(30):
        await server.publish(FINDING_CREATED, {"id": f"f{i}"})
    await server.publish(CRAWL_PROGRESS, {"job_id": "j1", "fetched": 1})
    for i in range(30, 60):
        await server.publish(FINDING_CREATED, {"id": f"f{i}"})

    await asyncio.sleep(3.0)

    await client.stop()
    await server.stop()

    important_received = [t for t, d in received if t == CRAWL_PROGRESS]
    critical_received = [t for t, d in received if t == FINDING_CREATED]

    assert len(critical_received) > 20, (
        f"Expected most CRITICAL delivered; got {len(critical_received)}"
    )
    assert len(important_received) == 1, (
        f"IMPORTANT event starved by CRITICAL! received={received}"
    )
