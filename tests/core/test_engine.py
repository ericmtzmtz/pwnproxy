import asyncio
import pytest

from pwnproxy.core.engine import ProxyEngine
from pwnproxy.core.hooks import HookBus


@pytest.mark.asyncio
async def test_proxy_engine_lifecycle():
    bus = HookBus()
    engine = ProxyEngine(hook_bus=bus)
    
    # Should start successfully
    await engine.start(port=8081)
    assert engine._master is not None
    assert engine._task is not None
    
    # Double start should raise
    with pytest.raises(RuntimeError):
        await engine.start(port=8082)
        
    # Stop should clear master
    engine.stop()
    assert engine._master is None
    
    # Double stop should not raise
    engine.stop()
