import asyncio
import pytest

from pwnproxy.core.hooks import HookBus


@pytest.mark.asyncio
async def test_hookbus_register_and_publish():
    bus = HookBus()
    queue = await bus.register("request")
    
    bus.publish("request", "flow_data")
    
    event = await asyncio.wait_for(queue.get(), timeout=1.0)
    assert event == "flow_data"


@pytest.mark.asyncio
async def test_hookbus_unknown_type():
    bus = HookBus()
    with pytest.raises(ValueError):
        await bus.register("invalid")
        
    with pytest.raises(ValueError):
        bus.publish("invalid", "data")


@pytest.mark.asyncio
async def test_hookbus_overflow():
    bus = HookBus(maxsize=2)
    queue = await bus.register("request")
    
    bus.publish("request", "1")
    bus.publish("request", "2")
    bus.publish("request", "3")  # Should drop "1"
    
    assert queue.qsize() == 2
    assert await queue.get() == "2"
    assert await queue.get() == "3"
