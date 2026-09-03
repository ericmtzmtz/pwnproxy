import asyncio
import pytest
from unittest.mock import patch

from pwnproxy.shared.hooks import HookBus, _HookChannelQueue


class TestHookBus:
    @pytest.mark.asyncio
    async def test_publish_with_no_subscribers(self):
        """Test that publishing to a channel with no subscribers is discarded."""
        bus = HookBus()
        
        # Should not raise an exception
        bus.publish("test_channel", "test_data")
        
        # Verify no subscribers were created
        assert bus.get_subscriber_count("test_channel") == 0
        assert not bus.has_subscribers("test_channel")

    @pytest.mark.asyncio
    async def test_publish_with_subscribers_delivers(self):
        """Test that publishing to a channel with subscribers delivers the data."""
        bus = HookBus()
        queue = bus.register("test_channel")
        
        # Publish data
        bus.publish("test_channel", "test_data")
        
        # Verify data was delivered
        data = await queue.get()
        assert data == "test_data"

    @pytest.mark.asyncio
    async def test_multiple_subscribers(self):
        """Test that data is delivered to all subscribers."""
        bus = HookBus()
        queue1 = bus.register("test_channel")
        queue2 = bus.register("test_channel")
        
        # Verify subscriber count
        assert bus.get_subscriber_count("test_channel") == 2
        assert bus.has_subscribers("test_channel")
        
        # Publish data
        bus.publish("test_channel", "test_data")
        
        # Verify both subscribers received the data
        data1 = await queue1.get()
        data2 = await queue2.get()
        assert data1 == "test_data"
        assert data2 == "test_data"

    @pytest.mark.asyncio
    async def test_multiple_channels(self):
        """Test data is delivered to correct channels only."""
        bus = HookBus()
        queue1 = bus.register("channel1")
        queue2 = bus.register("channel2")
        
        # Publish to different channels
        bus.publish("channel1", "data1")
        bus.publish("channel2", "data2")
        
        # Verify data is delivered to correct channels
        data1 = await queue1.get()
        data2 = await queue2.get()
        assert data1 == "data1"
        assert data2 == "data2"

    @pytest.mark.asyncio
    async def test_dynamic_channel_registration(self):
        """Test that channels can be registered dynamically."""
        bus = HookBus()
        
        # Initially no channels
        assert bus.get_subscriber_count("new_channel") == 0
        
        # Register a subscriber, which should register the channel
        queue = bus.register("new_channel")
        assert bus.get_subscriber_count("new_channel") == 1
        assert bus.has_subscribers("new_channel")
        
        # Publish to the new channel
        bus.publish("new_channel", "test_data")
        data = await queue.get()
        assert data == "test_data"

    @pytest.mark.asyncio
    async def test_channel_stats(self):
        """Test channel statistics."""
        bus = HookBus()
        
        # Initially empty
        assert bus.get_channel_stats() == {}
        
        # Add subscribers to different channels
        bus.register("channel1")
        bus.register("channel1")
        bus.register("channel2")
        
        # Check stats
        stats = bus.get_channel_stats()
        assert stats == {"channel1": 2, "channel2": 1}

    @pytest.mark.asyncio
    async def test_publish_warning_for_empty_channel(self):
        """Test that warning is logged when publishing to empty channel."""
        bus = HookBus()
        
        with patch.object(bus, '_warned_channels', set()) as warned_channels:
            # First publish to empty channel should trigger warning
            bus.publish("empty_channel", "test_data")
            
            # Channel should be in warned_channels
            assert "empty_channel" in warned_channels
            
            # Second publish should not trigger warning again
            bus.publish("empty_channel", "test_data2")
            # Only one warning should have been recorded
            assert len(warned_channels) == 1

    @pytest.mark.asyncio
    async def test_queue_overflow_handling(self):
        """Test that queue overflow is handled gracefully.

        QoS semantics replaced the old drop-oldest policy: a BEST_EFFORT
        channel that is full drops the INCOMING event (put_nowait returns
        False) and keeps the buffered ones. CRITICAL events are never dropped
        (they retry in-memory)."""
        from pwnproxy.shared.bus.qos import QoSClassifiedQueue
        from pwnproxy.shared.bus.topics import QoSClass

        bus = HookBus()
        qq = QoSClassifiedQueue(QoSClass.BEST_EFFORT, maxsize=2)
        queue = _HookChannelQueue("best.channel", qq)
        bus._subscribers["best.channel"] = [queue]
        bus._subscriber_counts["best.channel"] = 1

        # Fill the queue to capacity
        assert queue.put_nowait("item1") is True
        assert queue.put_nowait("item2") is True

        # BEST_EFFORT on full → drop the incoming event, keep buffered ones.
        assert queue.put_nowait("overflow_item") is False

        data1 = await queue.get()
        assert data1 == "item1"
        data2 = await queue.get()
        assert data2 == "item2"
        # The overflow item was dropped, so the queue is now empty.
        assert queue.qsize == 0

    @pytest.mark.asyncio
    async def test_critical_event_not_dropped_on_full(self):
        """CRITICAL (e.g. finding) on a full queue retries in-memory, never drops."""
        from pwnproxy.shared.bus.qos import QoSClassifiedQueue
        from pwnproxy.shared.bus.topics import QoSClass

        bus = HookBus()
        qq = QoSClassifiedQueue(QoSClass.CRITICAL, maxsize=1)
        queue = _HookChannelQueue("finding", qq)
        bus._subscribers["finding"] = [queue]
        bus._subscriber_counts["finding"] = 1

        queue.put_nowait("first")
        # Queue full → CRITICAL buffers for retry, producer sees success.
        assert queue.put_nowait("finding-event") is True
        assert queue.dropped == 0

        data1 = await queue.get()
        assert data1 == "first"
        data2 = await queue.get()
        assert data2 == "finding-event"

    @pytest.mark.asyncio
    async def test_pending_buffer_is_bounded(self):
        """Publishing floods to a channel with no subscriber keeps only the newest."""
        from pwnproxy.shared.hooks import _PENDING_CAP

        bus = HookBus()
        # Flood well past the cap with no subscriber registered.
        total = _PENDING_CAP + 50
        for i in range(total):
            bus.publish("nobody.home", f"msg-{i}")
        pending = bus._pending["nobody.home"]
        assert len(pending) == _PENDING_CAP
        # Oldest 50 messages dropped; the newest survive for the first subscriber.
        assert pending[0] == f"msg-{total - _PENDING_CAP}"
        assert pending[-1] == f"msg-{total - 1}"

    @pytest.mark.asyncio
    async def test_best_effort_channel_drops_incoming_on_full(self):
        """BEST_EFFORT HookBus channel (e.g. raw flow) drops under pressure but
        the producer's publish() never raises."""
        from pwnproxy.shared.bus.qos import QoSClassifiedQueue
        from pwnproxy.shared.bus.topics import QoSClass

        bus = HookBus()
        qq = QoSClassifiedQueue(QoSClass.BEST_EFFORT, maxsize=1)
        queue = _HookChannelQueue("flow", qq)
        bus._subscribers["flow"] = [queue]
        bus._subscriber_counts["flow"] = 1

        queue.put_nowait("first")
        # publish() is fire-and-forget; the incoming item is dropped on full.
        bus.publish("flow", {"id": 1})  # must not raise
        assert queue.dropped == 1

        data = await queue.get()
        assert data == "first"

    @pytest.mark.asyncio
    async def test_hookbus_no_longer_filters_scope(self):
        """Test that HookBus no longer applies scope filtering (delegated to FlowFilter)."""
        bus = HookBus()
        
        # set_scope_filter still exists but is deprecated and does nothing
        bus.set_scope_filter(lambda url: False)  # This filter should be IGNORED
        
        queue = bus.register("request")
        
        # Publish data that would have been filtered before
        bus.publish("request", {"url": "http://evil.com/test"})
        
        # Data should still be delivered (HookBus no longer filters)
        data = await queue.get()
        assert data == {"url": "http://evil.com/test"}

    @pytest.mark.asyncio
    async def test_scope_filter_not_applied_to_non_flow_objects(self):
        """Test that scope filter is not applied to non-Flow objects."""
        bus = HookBus()
        
        def mock_scope_filter(flow):
            return False  # Filter everything
        
        bus.set_scope_filter(mock_scope_filter)
        queue = bus.register("finding")
        
        # Publish finding (should not be filtered)
        bus.publish("finding", {"type": "xss", "severity": "high"})
        
        # Data should be delivered despite scope filter
        data = await queue.get()
        assert data == {"type": "xss", "severity": "high"}