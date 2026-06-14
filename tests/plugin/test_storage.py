import asyncio
import json
import os
from pathlib import Path

import pytest
import pytest_asyncio

from pwnproxy.plugins.core.base import Finding, PluginMetadata
from pwnproxy.plugins.core.storage import PluginOutputStorage, UnifiedFinding

@pytest_asyncio.fixture(scope="function")
async def storage_fixture(tmp_path_factory):
    db_path = tmp_path_factory.mktemp("db") / "findings_test.db"
    store = PluginOutputStorage(str(db_path))
    await store.create_tables()
    yield store
    await store.engine.dispose()

@pytest.mark.asyncio
async def test_save_finding(storage_fixture):
    finding = Finding(
        scanner="testscanner",
        url="http://example.com",
        method="GET",
        param_name="id",
        param_location="query",
        technique="boolean",
        severity="high",
        confidence="confirmed",
        payload="' OR 1=1--",
        evidence="Response length diff",
    )
    await storage_fixture.save(finding)
    async with storage_fixture.session_factory() as session:
        result = await session.execute(
            "SELECT COUNT(*) FROM findings WHERE scanner=:scanner",
            {"scanner": "testscanner"},
        )
        count = result.scalar_one()
        assert count == 1

@pytest.mark.asyncio
async def test_save_with_extra(storage_fixture):
    finding = Finding(
        scanner="extrascanner",
        url="http://example.org",
        method="POST",
        param_name="q",
        param_location="body",
        technique="error",
        severity="medium",
        confidence="tentative",
        payload="<script>alert(1)</script>",
        evidence="JS error",
        extra={"cve": "2023-1234", "impact": "xss"},
    )
    await storage_fixture.save(finding)
    async with storage_fixture.session_factory() as session:
        result = await session.execute(
            "SELECT extra FROM findings WHERE scanner=:scanner",
            {"scanner": "extrascanner"},
        )
        extra_json = result.scalar_one()
        data = json.loads(extra_json)
        assert data["cve"] == "2023-1234"
        assert data["impact"] == "xss"

class MockCustomStorage:
    def __init__(self):
        self.saved = None
    async def save(self, item):
        self.saved = item

@pytest.mark.asyncio
async def test_custom_storage(storage_fixture, monkeypatch):
    meta = PluginMetadata(name="mock", version="0.1", storage=MockCustomStorage)
    finding = Finding(
        scanner="customscanner",
        url="http://custom",
        method="GET",
        param_name="a",
        param_location="query",
        technique="test",
        severity="low",
        confidence="tentative",
        payload="test",
        evidence="none",
    )
    setattr(finding, "metadata", meta)
    captured = {}
    async def fake_init(self, *args, **kwargs):
        captured["instance"] = self
        return self
    monkeypatch.setattr(MockCustomStorage, "__call__", fake_init, raising=False)
    await storage_fixture.save(finding)
    assert "instance" in captured
    assert captured["instance"].saved == finding
