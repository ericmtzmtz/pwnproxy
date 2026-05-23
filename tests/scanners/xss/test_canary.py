from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from pwnproxy.scanners.xss.canary import CanaryStore
from pwnproxy.scanners.xss.models import XssCanary


@pytest.mark.asyncio
async def test_generate_format():
    storage = MagicMock()
    store = CanaryStore(storage)
    canary = store.generate()
    assert canary.startswith("pwnxss-")
    assert len(canary) >= 13


@pytest.mark.asyncio
async def test_store_and_scan():
    storage = MagicMock()
    storage.save_canary = AsyncMock()
    storage.mark_canary_found = AsyncMock()
    store = CanaryStore(storage)
    canary = store.generate()
    await store.store(canary, "http://source.com/page", "q", "query")
    assert canary in store._active
    storage.save_canary.assert_called_once()

    matches = await store.scan_response(f"hello {canary} world", "http://reflected.com/other")
    assert len(matches) == 1
    assert matches[0].canary_value == canary
    assert matches[0].source_url == "http://source.com/page"
    assert matches[0].found_url == "http://reflected.com/other"


@pytest.mark.asyncio
async def test_scan_no_match():
    storage = MagicMock()
    storage.save_canary = AsyncMock()
    store = CanaryStore(storage)
    canary = store.generate()
    await store.store(canary, "http://source.com", "q", "query")
    matches = await store.scan_response("no canary here", "http://target.com/")
    assert len(matches) == 0


@pytest.mark.asyncio
async def test_cleanup():
    storage = MagicMock()
    storage.save_canary = AsyncMock()
    storage.cleanup_old_canaries = AsyncMock(return_value=1)
    store = CanaryStore(storage)
    old = XssCanary(
        canary_value="pwnxss-old1234",
        source_url="http://old.com",
        param_name="q",
        param_location="query",
        injected_at=datetime(2000, 1, 1),
    )
    store._active["pwnxss-old1234"] = old
    count = await store.cleanup(max_age_hours=1)
    assert count >= 1
    assert "pwnxss-old1234" not in store._active


@pytest.mark.asyncio
async def test_load_active():
    storage = MagicMock()
    storage.get_active_canaries = AsyncMock(return_value=[
        XssCanary(
            id=1, canary_value="pwnxss-abc123",
            source_url="http://test.com", param_name="q",
            param_location="query", injected_at=datetime.now(),
        )
    ])
    store = CanaryStore(storage)
    await store.load_active()
    assert "pwnxss-abc123" in store._active
