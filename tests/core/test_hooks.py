import asyncio
import pytest
from unittest.mock import patch

from pwnproxy.shared.hooks import HookBus


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
        """Test that queue overflow is handled gracefully."""
        bus = HookBus(maxsize=2)  # Very small queue
        queue = bus.register("test_channel")
        
        # Fill the queue
        queue.put_nowait("item1")
        queue.put_nowait("item2")
        
        # This should trigger overflow handling - drops oldest, adds newest
        bus.publish("test_channel", "overflow_item")
        
        # Queue should now contain: ["item2", "overflow_item"]
        # Get first item (should be the second original item)
        data1 = await queue.get()
        assert data1 == "item2"
        
        # Get second item (should be the overflow item)
        data2 = await queue.get()
        assert data2 == "overflow_item"
        
        # Verify the queue has space for new items
        queue.put_nowait("new_item")
        data3 = await queue.get()
        assert data3 == "new_item"

    @pytest.mark.asyncio
    async def test_scope_filter_with_flow_objects(self):
        """Test that scope filter is applied to Flow objects."""
        bus = HookBus()
        
        def mock_scope_filter(url: str) -> bool:
            return "allowed" in url
        
        bus.set_scope_filter(mock_scope_filter)
        queue = bus.register("request")
        
        # Publish flow that should be filtered out (no "allowed" in URL)
        filtered_data = {"url": "http://example.com/blocked"}
        bus.publish("request", filtered_data)
        
        # Publish flow that should pass through
        allowed_data = {"url": "http://example.com/allowed"}
        bus.publish("request", allowed_data)
        
        # Check that only the allowed data was published
        data = await queue.get()
        assert data == allowed_data
        
        # Queue should now be empty
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(queue.get(), timeout=0.1)

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