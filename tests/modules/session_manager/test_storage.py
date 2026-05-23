import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from pwnproxy.modules.session_manager.models import TokenCandidate
from pwnproxy.modules.session_manager.storage import TokenStorage


@pytest.mark.asyncio
async def test_save_new_token():
    with tempfile.TemporaryDirectory() as tmp:
        db = str(Path(tmp) / "test.db")
        storage = TokenStorage(db_path=db)
        await storage.init()

        candidate = TokenCandidate(
            token_type="jwt",
            token_value="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.a1b2c3",
            label="Bearer",
            source_url="http://target.com",
        )
        await storage.save([candidate])

        results = await storage.query()
        assert len(results) == 1
        assert results[0].token_type == "jwt"
        assert results[0].ref_count == 1

        await storage.close()


@pytest.mark.asyncio
async def test_save_duplicate_increments_ref_count():
    with tempfile.TemporaryDirectory() as tmp:
        db = str(Path(tmp) / "test.db")
        storage = TokenStorage(db_path=db)
        await storage.init()

        candidate = TokenCandidate(
            token_type="jwt",
            token_value="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.a1b2c3",
            label="Bearer",
            source_url="http://target.com",
        )
        await storage.save([candidate])
        await storage.save([candidate])

        results = await storage.query()
        assert len(results) == 1
        assert results[0].ref_count == 2

        await storage.close()


@pytest.mark.asyncio
async def test_query_by_type():
    with tempfile.TemporaryDirectory() as tmp:
        db = str(Path(tmp) / "test.db")
        storage = TokenStorage(db_path=db)
        await storage.init()

        await storage.save([
            TokenCandidate(token_type="jwt", token_value="jwt1", label="a", source_url="http://x.com"),
            TokenCandidate(token_type="cookie", token_value="cookie1", label="b", source_url="http://x.com"),
        ])

        jwt_results = await storage.query(token_type="jwt")
        assert len(jwt_results) == 1
        assert jwt_results[0].token_type == "jwt"

        await storage.close()


@pytest.mark.asyncio
async def test_query_by_search():
    with tempfile.TemporaryDirectory() as tmp:
        db = str(Path(tmp) / "test.db")
        storage = TokenStorage(db_path=db)
        await storage.init()

        await storage.save([
            TokenCandidate(token_type="jwt", token_value="abc123", label="first", source_url="http://x.com"),
            TokenCandidate(token_type="jwt", token_value="def456", label="second", source_url="http://x.com"),
        ])

        results = await storage.query(search="abc")
        assert len(results) == 1
        assert results[0].token_value == "abc123"

        await storage.close()


@pytest.mark.asyncio
async def test_delete_old():
    with tempfile.TemporaryDirectory() as tmp:
        db = str(Path(tmp) / "test.db")
        storage = TokenStorage(db_path=db)
        await storage.init()

        old = TokenCandidate(token_type="jwt", token_value="old", label="old", source_url="http://x.com")
        new = TokenCandidate(token_type="jwt", token_value="new", label="new", source_url="http://x.com")
        await storage.save([old, new])

        deleted = await storage.delete_old(before=datetime.now() + timedelta(days=1))
        assert deleted == 2

        await storage.close()
