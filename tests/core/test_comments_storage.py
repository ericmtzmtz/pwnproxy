import asyncio
import tempfile
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from pwnproxy.shared.comments.storage import FlowCommentStorage
from pwnproxy.shared.db import Base


@pytest.fixture
def storage_engine():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        db_path = Path(tmp) / "traffic.db"
        engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")

        async def _init():
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

        asyncio.run(_init())
        storage = FlowCommentStorage(engine)
        yield storage
        asyncio.run(engine.dispose())


class TestFlowCommentStorage:
    def test_create_defaults(self, storage_engine):
        async def _run():
            row = await storage_engine.create(flow_id=1, body="hello")
            assert row["body"] == "hello"
            assert row["kind"] == "note"
            assert row["resolved"] is False
            assert row["author"] is None
            assert row["created_at"] is not None
            assert row["flow_id"] == 1
            return row

        asyncio.run(_run())

    def test_create_with_kind_and_author(self, storage_engine):
        async def _run():
            row = await storage_engine.create(flow_id=1, body="flag this", kind="flag", resolved=True, author="local")
            assert row["kind"] == "flag"
            assert row["resolved"] is True
            assert row["author"] == "local"

        asyncio.run(_run())

    def test_invalid_kind(self, storage_engine):
        async def _run():
            with pytest.raises(ValueError):
                await storage_engine.create(flow_id=1, body="x", kind="bad")

        asyncio.run(_run())

    def test_list_by_flow(self, storage_engine):
        async def _run():
            await storage_engine.create(flow_id=1, body="a")
            await storage_engine.create(flow_id=1, body="b")
            await storage_engine.create(flow_id=2, body="other")
            rows = await storage_engine.list_by_flow(1)
            assert len(rows) == 2
            assert [r["body"] for r in rows] == ["a", "b"]

        asyncio.run(_run())

    def test_update_and_updated_at(self, storage_engine):
        async def _run():
            row = await storage_engine.create(flow_id=1, body="orig")
            orig_updated = row["updated_at"]
            updated = await storage_engine.update(row["id"], body="new", kind="todo", resolved=True)
            assert updated["body"] == "new"
            assert updated["kind"] == "todo"
            assert updated["resolved"] is True
            assert updated["updated_at"] != orig_updated or updated["updated_at"] is not None

        asyncio.run(_run())

    def test_delete_and_count(self, storage_engine):
        async def _run():
            r1 = await storage_engine.create(flow_id=1, body="a")
            await storage_engine.create(flow_id=1, body="b")
            assert await storage_engine.count_by_flow(1) == 2
            assert await storage_engine.delete(r1["id"]) is True
            assert await storage_engine.count_by_flow(1) == 1
            assert await storage_engine.delete(99999) is False

        asyncio.run(_run())

    def test_delete_by_flow(self, storage_engine):
        async def _run():
            await storage_engine.create(flow_id=1, body="a")
            await storage_engine.create(flow_id=1, body="b")
            n = await storage_engine.delete_by_flow(1)
            assert n == 2
            assert await storage_engine.count_by_flow(1) == 0

        asyncio.run(_run())
