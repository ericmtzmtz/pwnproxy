"""FP-triage v0: heuristic scorer, pipeline zones, LLM judge, history, REST endpoints."""
import asyncio
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine

from pwnproxy.ai.llm.testing import FakeLLMClient
from pwnproxy.ai.triage import TriagePipeline, TriageConfig, score_finding
from pwnproxy.ai.triage.judge import JudgeVerdict, LLMJudge
from pwnproxy.plugins.core.base import Finding
from pwnproxy.shared.db import Base
from pwnproxy.shared.findings.storage import FindingStorage, TriageHistoryORM
from pwnproxy.transport.rest.app import app


class FakeHookBus:
    def __init__(self):
        self.published: list[tuple[str, dict]] = []

    def publish(self, topic, payload):
        self.published.append((topic, payload))


def _finding(**overrides) -> Finding:
    base = dict(
        scanner="sqli", url="http://t/x?id=1", method="GET", param_name="id",
        param_location="query", technique="boolean-blind", severity="high",
        payload="", evidence="", confidence="tentative",
    )
    base.update(overrides)
    return Finding(**base)


async def _make_storage():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    st = FindingStorage(engine)
    await st.create_table()
    return engine, st


class TestHeuristic:
    def test_noise_signals_score_low(self):
        res = score_finding({"id": 1, "evidence": "", "payload": "", "confidence": "tentative"})
        assert res.score <= 0.3
        assert "no_evidence" in res.reasons
        assert "scanner_noise" in res.reasons

    def test_confident_with_evidence_and_request_scores_high(self):
        row = {
            "evidence": "x" * 150 + " ' OR 1=1", "payload": "' OR 1=1",
            "confidence": "confident", "request_data": {"request": "GET / HTTP/1.1"},
        }
        res = score_finding(row)
        assert res.score >= 0.7
        assert "strong_evidence" in res.reasons
        assert "request_context" in res.reasons

    def test_gray_zone_example(self):
        row = {
            "evidence": "x" * 130 + " <svg>", "payload": "<svg>",
            "confidence": "tentative", "request_data": None,
        }
        res = score_finding(row)
        assert 0.3 < res.score < 0.7

    def test_clamped(self):
        res = score_finding({"id": 1, "evidence": "", "confidence": "tentative"})
        assert 0.0 <= res.score <= 1.0


@pytest.fixture
def triage_env():
    engine = None

    async def _setup():
        nonlocal engine
        engine, st = await _make_storage()
        return st

    st = asyncio.run(_setup())
    yield st
    FindingStorage.on_saved = None


class TestPipeline:
    def test_auto_true_without_llm(self):
        async def _run():
            _, st = await _make_storage()
            bus = FakeHookBus()
            pipe = TriagePipeline(lambda: st, hook_bus=bus, judge=None, config=TriageConfig())
            fid = await st.save(_finding(confidence="confident", evidence="y" * 140 + " PWN",
                                         payload="PWN", request_data={"r": 1}))
            row = await st.get(fid)
            await pipe.handle(row)
            updated = await st.get(fid)
            assert updated["triage_verdict"] == "true_positive"
            assert updated["triage_method"] == "heuristic"
            topics = [t for t, _ in bus.published]
            assert "triage.updated" in topics

        asyncio.run(_run())

    def test_auto_false_without_llm(self):
        async def _run():
            _, st = await _make_storage()
            pipe = TriagePipeline(lambda: st, judge=None, config=TriageConfig())
            fid = await st.save(_finding())
            await pipe.handle(await st.get(fid))
            updated = await st.get(fid)
            assert updated["triage_verdict"] == "false_positive"
            assert "no_evidence" in updated["triage_reason"]

        asyncio.run(_run())

    def test_gray_zone_goes_to_judge(self):
        async def _run():
            _, st = await _make_storage()
            bus = FakeHookBus()
            fake = FakeLLMClient().push(JudgeVerdict(verdict="false_positive", confidence=0.85, reason="scanner_noise"))
            pipe = TriagePipeline(lambda: st, hook_bus=bus, judge=LLMJudge(fake), config=TriageConfig())
            fid = await st.save(_finding(evidence="z" * 130 + " <svg>", payload="<svg>"))
            await pipe.handle(await st.get(fid))
            provisional = await st.get(fid)
            assert provisional["triage_verdict"] == "uncertain"
            pipe.start()
            await pipe.queue.join()
            await pipe.stop()
            final = await st.get(fid)
            assert final["triage_verdict"] == "false_positive"
            assert final["triage_method"] == "llm"
            assert len(fake.structured_calls) == 1

        asyncio.run(_run())

    def test_judge_unavailable_stays_uncertain(self):
        async def _run():
            _, st = await _make_storage()
            fake = FakeLLMClient().push(RuntimeError("ollama down"))
            pipe = TriagePipeline(lambda: st, judge=LLMJudge(fake), config=TriageConfig())
            fid = await st.save(_finding(evidence="z" * 130))
            await pipe.handle(await st.get(fid))
            pipe.start()
            await pipe.queue.join()
            await pipe.stop()
            final = await st.get(fid)
            assert final["triage_verdict"] == "uncertain"
            assert final["triage_method"] == "heuristic"

        asyncio.run(_run())

    def test_pipeline_failure_keeps_finding(self):
        async def _run():
            _, st = await _make_storage()

            class Broken(FindingStorage):
                async def set_triage(self, *a, **kw):
                    raise RuntimeError("boom")

            broken = Broken(st._engine)
            pipe = TriagePipeline(lambda: broken, judge=None, config=TriageConfig())
            fid = await st.save(_finding())
            await pipe.handle(await st.get(fid))  # must not raise
            row = await st.get(fid)
            assert row["triage_verdict"] is None  # stays pending, finding persisted

        asyncio.run(_run())

    def test_human_feedback_overwrites_and_records_history(self):
        async def _run():
            _, st = await _make_storage()
            pipe = TriagePipeline(lambda: st, judge=None, config=TriageConfig())
            fid = await st.save(_finding(confidence="confident", evidence="y" * 140 + " PWN", payload="PWN"))
            await pipe.handle(await st.get(fid))
            await pipe.handle_human_feedback(fid, "false_positive", "dup of #7")
            final = await st.get(fid)
            assert final["triage_verdict"] == "false_positive"
            assert final["triage_method"] == "human"
            async with st._engine.begin() as conn:
                hist = (await conn.execute(
                    select(TriageHistoryORM.verdict, TriageHistoryORM.method)
                    .where(TriageHistoryORM.finding_id == fid)
                    .order_by(TriageHistoryORM.id))).all()
            assert hist == [("true_positive", "heuristic"), ("false_positive", "human")]

        asyncio.run(_run())


class TestMigration:
    def test_additive_migration_on_legacy_table(self):
        async def _run():
            engine = create_async_engine("sqlite+aiosqlite:///:memory:")
            from sqlalchemy import text
            async with engine.begin() as conn:
                await conn.execute(text("""
                    CREATE TABLE findings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, scanner VARCHAR(50) NOT NULL,
                        url TEXT NOT NULL, method VARCHAR(10), param_name VARCHAR(255),
                        param_location VARCHAR(50), technique VARCHAR(100), severity VARCHAR(20),
                        confidence VARCHAR(20), payload TEXT, evidence TEXT, timestamp DATETIME,
                        extra JSON
                    )
                """))
            st = FindingStorage(engine)
            await st.create_table()  # adds request_data + triage_* columns
            fid = await st.save(_finding())
            assert fid >= 1
            row = await st.get(fid)
            assert row["triage_verdict"] is None

        asyncio.run(_run())


class TestApi:
    @pytest.fixture
    def client(self):
        async def _init():
            engine, st = await _make_storage()
            f1 = _finding(evidence="q" * 140 + " PWN", payload="PWN", confidence="confident")
            id1 = await st.save(f1)
            await st.set_triage(id1, "true_positive", "heuristic", 0.9, "strong_evidence")
            id2 = await st.save(_finding(url="http://t/y?q=2", param_name="q"))
            return engine, st, id1, id2

        engine, st, id1, id2 = asyncio.run(_init())
        bus = FakeHookBus()
        app.state.hook_bus = bus
        app.state.triage_pipeline = None

        class _SM:
            def get_scanner_engine(self_inner):
                return engine

        app.state.session_manager = _SM()
        with TestClient(app) as c:
            yield c, st, id1, id2, bus
        FindingStorage.on_saved = None
        asyncio.run(engine.dispose())

    def test_feedback_overrides_to_human(self, client):
        c, st, id1, _, bus = client
        r = c.patch(f"/api/v1/findings/{id1}/feedback", json={"verdict": "false_positive", "reason": "dup"})
        assert r.status_code == 200
        body = r.json()["finding"]
        assert body["triage_verdict"] == "false_positive"
        assert body["triage_method"] == "human"
        assert any(t == "triage.updated" for t, _ in bus.published)

    def test_feedback_404_and_422(self, client):
        c, *_ = client
        assert c.patch("/api/v1/findings/9999/feedback", json={"verdict": "false_positive"}).status_code == 404
        assert c.patch("/api/v1/findings/1/feedback", json={"verdict": "bogus"}).status_code == 422

    def test_export_jsonl_ground_truth(self, client):
        c, st, id1, id2, _ = client

        async def _mark_human():
            await st.set_triage(id2, "false_positive", "human", None, "manual")

        asyncio.run(_mark_human())
        r = c.get("/api/v1/findings/export-triage")
        assert r.status_code == 200
        lines = [json.loads(l) for l in r.text.strip().splitlines()]
        assert len(lines) == 2
        by_id = {d["id"]: d for d in lines}
        assert by_id[id1]["ground_truth"] is None          # automatic verdict -> no ground truth
        assert by_id[id2]["ground_truth"] == "false_positive"  # human verdict -> ground truth
        assert "features" in by_id[id1]

    def test_verdict_filter(self, client):
        c, st, id1, id2, _ = client
        r = c.get("/api/v1/findings", params={"verdict": "true_positive"})
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 1
        assert data["items"][0]["id"] == id1


class TestWsEvent:
    def test_triage_updated_reaches_ws_client(self):
        from pwnproxy.shared.hooks import HookBus
        bus = HookBus()
        app.state.hook_bus = bus
        FindingStorage.on_saved = None
        with TestClient(app) as c:
            with c.websocket_connect("/ws/events") as ws:
                bus.publish("triage.updated", {
                    "finding_id": 7, "verdict": "false_positive",
                    "method": "llm", "score": 0.85, "reason": "scanner_noise",
                })
                data = ws.receive_text()
                parsed = json.loads(data)
                assert parsed["type"] == "triage.updated"
                assert parsed["finding_id"] == 7
                assert parsed["verdict"] == "false_positive"
