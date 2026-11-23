"""``finding.stored``: the persisted-row event the WebSocket relays forward.

The contract is fixed by ``openspec/changes/live-plugin-findings``: the channel
carries the **stored row** (``findings`` columns) plus ``session_id``, is
classified ``CRITICAL`` in the bus QoS table, and publishing it is best effort
(the row is already saved, so a bus failure must not fail the caller).
"""

from pwnproxy.shared.bus.topics import FINDING_STORED, HOOKBUS_QOS
from pwnproxy.shared.findings.events import (
    FINDING_STORED_CHANNEL,
    publish_stored_finding,
    stored_event,
)
from pwnproxy.shared.hooks import HookBus


def _row(**overrides) -> dict:
    """A minimal persisted row (only the columns these tests care about)."""
    row = {
        "id": 7,
        "scanner": "sqli",
        "url": "http://target.local/item?id=1",
        "method": "GET",
        "param_name": "id",
        "param_location": "query",
        "technique": "error-based",
        "severity": "high",
        "confidence": "confirmed",
        "payload": "' OR 1=1-- -",
        "evidence": "SQL syntax error",
        "timestamp": None,
        "extra": {},
        "request_data": None,
        "triage_score": None,
        "triage_verdict": None,
        "triage_method": None,
        "triage_reason": None,
    }
    row.update(overrides)
    return row


class TestStoredEventShape:
    def test_the_row_gains_the_session_id(self):
        assert stored_event(_row(), "demo") == {**_row(), "session_id": "demo"}

    def test_without_a_session_the_field_is_not_invented(self):
        assert "session_id" not in stored_event(_row(), None)

    def test_the_input_row_is_not_mutated(self):
        row = _row()
        stored_event(row, "demo")
        assert row == _row()


class TestChannelIsCritical:
    def test_the_channel_name_is_the_canonical_topic(self):
        assert FINDING_STORED_CHANNEL == FINDING_STORED == "finding.stored"

    def test_the_bus_classifies_it_as_critical(self):
        from pwnproxy.shared.bus.topics import QoSClass

        assert HOOKBUS_QOS[FINDING_STORED] is QoSClass.CRITICAL

    def test_a_full_queue_keeps_the_event_for_retry(self):
        """CRITICAL policy (spec ``event-qos``): no drop when the queue is full."""
        from pwnproxy.shared.bus.qos import QoSClassifiedQueue

        queue = QoSClassifiedQueue(HOOKBUS_QOS[FINDING_STORED], maxsize=1)

        assert queue.put_nowait(FINDING_STORED, _row(id=1)) is True
        assert queue.put_nowait(FINDING_STORED, _row(id=2)) is True
        # Neither event is dropped: one is queued, the other waits in the retry
        # buffer (private by design; ``dropped`` is the observable contract).
        assert (queue.dropped, queue.qsize) == (0, 1)


class TestPublishStoredFinding:
    def test_it_publishes_the_row_on_the_channel(self):
        bus = HookBus()
        queue = bus.register(FINDING_STORED)

        published = publish_stored_finding(bus, _row(), "demo")

        assert (published, queue.has_data) == ({**_row(), "session_id": "demo"}, True)

    def test_without_a_bus_nothing_happens(self):
        assert publish_stored_finding(None, _row(), "demo") is None

    def test_a_broken_bus_is_logged_not_raised(self, caplog):
        class _BrokenBus:
            def publish(self, channel, data):
                raise RuntimeError("subscriber gone")

        with caplog.at_level("WARNING"):
            published = publish_stored_finding(_BrokenBus(), _row(), "demo")

        assert published == {**_row(), "session_id": "demo"}
        assert "could not publish finding.stored for id=7" in caplog.text
