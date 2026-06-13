import asyncio
import pytest

from pwnproxy.services.proxy.engine import ProxyEngine
from pwnproxy.shared.hooks import HookBus


@pytest.mark.asyncio
async def test_proxy_engine_lifecycle():
    bus = HookBus()
    engine = ProxyEngine(hook_bus=bus)
    
    # Should start successfully
    engine.configure(port=8081)
    await engine.start()
    assert engine._master is not None
    assert engine._task is not None
    
    # Double start should raise
    with pytest.raises(RuntimeError):
        await engine.start()
        
    # Stop should clear master
    engine.stop()
    assert engine._master is None
    
    # Double stop should not raise
    engine.stop()
