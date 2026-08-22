"""Tests for finding request_data capture (serialize + storage roundtrip)."""

import asyncio
import uuid
from datetime import datetime, timezone

import httpx
import pytest

from pwnproxy.shared.scan.replayer import _serialize_request


class TestSerializeRequest:
    def test_query_injection_request(self):
        req = httpx.Request(
            "GET",
            "http://example.com/page.php?page=../../../../../../etc/passwd",
            headers={"Host": "example.com"},
        )
        data = _serialize_request(req)
        assert data["method"] == "GET"
        assert data["url"] == "http://example.com/page.php?page=../../../../../../etc/passwd"
        assert data["headers"]["host"] == "example.com"  # httpx lowercases header names
        assert data["body"] is None

    def test_post_body_request(self):
        req = httpx.Request(
            "POST",
            "http://example.com/xxe",
            headers={"Host": "example.com", "Content-Type": "text/xml"},
            content=b"<root>&xxe;</root>",
        )
        data = _serialize_request(req)
        assert data["method"] == "POST"
        assert data["body"] == "<root>&xxe;</root>"
        assert data["headers"].get("content-type") == "text/xml"


class TestStorageRoundtrip:
    def test_save_load_request_data(self, tmp_path):
        from sqlalchemy.ext.asyncio import create_async_engine

        from pwnproxy.shared.db import Base
        from pwnproxy.shared.findings.storage import FindingStorage
        from pwnproxy.plugins.core.base import Finding as BaseFinding

        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/t.db")

        async def _init():
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

        asyncio.run(_init())

        storage = FindingStorage(engine)

        request_data = {
            "method": "GET",
            "url": "http://example.com/page.php?page=../../../../../../etc/passwd",
            "headers": {"host": "example.com"},
            "body": None,
        }

        finding = BaseFinding(
            scanner="lfi",
            url="http://example.com/page.php?page=x",
            method="GET",
            param_name="page",
            param_location="query",
            technique="path-traversal",
            severity="high",
            confidence="confirmed",
            payload="../../../../../../etc/passwd",
            evidence="root:x:0:0:",
            timestamp=datetime.now(timezone.utc),
            extra={"os": "unix"},
            request_data=request_data,
        )

        asyncio.run(storage.save(finding))
        rows = asyncio.run(storage.list("lfi"))
        assert len(rows) == 1
        row = rows[0]
        assert row["request_data"] == request_data
        assert row["payload"] == "../../../../../../etc/passwd"
        asyncio.run(engine.dispose())
