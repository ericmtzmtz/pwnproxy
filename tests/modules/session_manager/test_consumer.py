import asyncio
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from pwnproxy.shared.hooks import HookBus
from pwnproxy.shared.models import Flow
from pwnproxy.services.session.consumer import SessionConsumer


@pytest.mark.asyncio
async def test_consumer_processes_flow():
    hook_bus = HookBus()

    storage = MagicMock()
    storage.init = AsyncMock()
    storage.save = AsyncMock()
    storage.close = AsyncMock()
    storage.query = AsyncMock(return_value=[])

    consumer = SessionConsumer(hook_bus, storage=storage)
    await consumer.start()

    flow = Flow(
        id="f1", method="GET", url="http://target.com/api",
        request_headers={
            "authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.a1b2c3",
        },
        request_body=None, response_headers={}, response_body=None,
        status_code=200,
    )

    hook_bus.publish("response", flow)
    await asyncio.sleep(0.2)

    assert storage.save.called
    args = storage.save.call_args
    assert args is not None
    candidates = args[0][0]
    assert len(candidates) >= 1
    assert candidates[0].token_type == "jwt"

    await consumer.stop()


@pytest.mark.asyncio
async def test_consumer_lifecycle():
    hook_bus = HookBus()

    storage = MagicMock()
    storage.init = AsyncMock()
    storage.save = AsyncMock()
    storage.close = AsyncMock()
    storage.query = AsyncMock(return_value=[])

    consumer = SessionConsumer(hook_bus, storage=storage)

    assert not consumer._running
    await consumer.start()
    assert consumer._running

    await consumer.stop()
    assert not consumer._running
