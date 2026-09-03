"""TaskStore state machine: create queued, legal transitions, illegal rejected."""
import pytest

from pwnproxy.services.session.store import TaskStore
from pwnproxy.shared.task_model import create_task_engine, init_task_db


async def _store(tmp_path) -> TaskStore:
    engine = create_task_engine(str(tmp_path))
    await init_task_db(engine)
    s = TaskStore(engine)
    await s.init()
    return s


async def _mk(store, task_type="scan") -> str:
    return await store.create(task_type, {"url": "http://t/"}, session_name="t")


@pytest.mark.asyncio
async def test_create_starts_queued(tmp_path):
    store = await _store(tmp_path)
    try:
        tid = await _mk(store)
        task = await store.get(tid)
        assert task["status"] == "queued"
    finally:
        await store._engine.dispose()


@pytest.mark.asyncio
async def test_queued_to_running_to_completed_legal(tmp_path):
    store = await _store(tmp_path)
    try:
        tid = await _mk(store)
        await store.update(tid, status="running", progress=1, total=1)
        t = await store.get(tid)
        assert t["status"] == "running"
        assert t["progress"] == 1
        await store.update(tid, status="completed")
        t = await store.get(tid)
        assert t["status"] == "completed"
        assert t["completed_at"] is not None
    finally:
        await store._engine.dispose()


@pytest.mark.asyncio
async def test_illegal_completed_to_running_rejected(tmp_path):
    store = await _store(tmp_path)
    try:
        tid = await _mk(store)
        await store.update(tid, status="running")
        await store.update(tid, status="completed")
        # completed is terminal → running must be rejected without changing state.
        await store.update(tid, status="running", error="should not apply")
        t = await store.get(tid)
        assert t["status"] == "completed"
        assert t["error"] is None, "illegal transition must not write any fields"
    finally:
        await store._engine.dispose()


@pytest.mark.asyncio
async def test_running_to_cancelled_legal(tmp_path):
    store = await _store(tmp_path)
    try:
        tid = await _mk(store)
        await store.update(tid, status="running")
        ok = await store.cancel(tid)
        assert ok is True
        t = await store.get(tid)
        assert t["status"] == "cancelled"
    finally:
        await store._engine.dispose()


@pytest.mark.asyncio
async def test_queued_to_cancelled_legal(tmp_path):
    store = await _store(tmp_path)
    try:
        tid = await _mk(store)
        ok = await store.cancel(tid)
        assert ok is True
        t = await store.get(tid)
        assert t["status"] == "cancelled"
    finally:
        await store._engine.dispose()


@pytest.mark.asyncio
async def test_completed_cannot_be_cancelled(tmp_path):
    store = await _store(tmp_path)
    try:
        tid = await _mk(store)
        await store.update(tid, status="running")
        await store.update(tid, status="completed")
        ok = await store.cancel(tid)
        assert ok is True  # task exists; cancel is a no-op on terminal
        t = await store.get(tid)
        assert t["status"] == "completed"
    finally:
        await store._engine.dispose()


@pytest.mark.asyncio
async def test_transition_table(tmp_path):
    from pwnproxy.services.session.store import _task_transition_legal
    assert _task_transition_legal("queued", "failed") is True
    assert _task_transition_legal("running", "failed") is True
    assert _task_transition_legal("queued", "completed") is False
    assert _task_transition_legal("completed", "running") is False
    assert _task_transition_legal("failed", "cancelled") is False
    assert _task_transition_legal("running", "cancelled") is True
    assert _task_transition_legal("queued", "running") is True


@pytest.mark.asyncio
async def test_progress_update_without_status_ok(tmp_path):
    store = await _store(tmp_path)
    try:
        tid = await _mk(store)
        await store.update(tid, status="running", progress=10, total=100)
        # progress-only update keeps status unchanged and stays legal (no-op state)
        await store.update(tid, progress=25)
        t = await store.get(tid)
        assert t["status"] == "running"
        assert t["progress"] == 25
    finally:
        await store._engine.dispose()
