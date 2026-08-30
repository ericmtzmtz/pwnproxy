"""Tests for LLM telemetry: ledger fields, fallback tracking, schema_retry, aggregation."""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock

from pwnproxy.ai.llm.client import CircuitBreaker, UnifiedLLMClient
from pwnproxy.ai.llm.errors import LLMUnavailable
from pwnproxy.ai.llm.models import LLMMessage, LLMRequest, LLMResponse
from pwnproxy.ai.llm.usage import UsageBase, UsageLedger
from pwnproxy.ai.llm.testing import RecordingProvider


def _req(text: str = "hello") -> LLMRequest:
    return LLMRequest(messages=[LLMMessage(role="user", content=text)])


def _ok_response(provider: str = "openai", model: str = "gpt-4") -> LLMResponse:
    return LLMResponse(text='{"ok": true}', provider=provider, model=model,
                       input_tokens=10, output_tokens=20, latency_ms=150)


def _read_all(engine) -> list:
    """Read all rows from ai_usage as raw tuples."""
    import asyncio as _aio
    async def _go():
        from sqlalchemy import text
        async with engine.connect() as conn:
            return (await conn.execute(text("SELECT * FROM ai_usage"))).fetchall()
    return _aio.get_event_loop().run_until_complete(_go())


# ── CircuitBreaker.circuit_state ────────────────────────────────────

class TestCircuitBreakerState:
    def test_initially_closed(self):
        cb = CircuitBreaker(threshold=3)
        assert cb.circuit_state("openai") == "closed"

    def test_open_after_threshold(self):
        cb = CircuitBreaker(threshold=2)
        cb.record_failure("openai")
        assert cb.circuit_state("openai") == "closed"
        cb.record_failure("openai")
        assert cb.circuit_state("openai") == "open"

    def test_half_open_after_success(self):
        cb = CircuitBreaker(threshold=2, cooldown_s=10)
        cb.record_failure("openai")
        cb.record_failure("openai")
        assert cb.circuit_state("openai") == "open"
        cb.record_success("openai")
        assert cb.circuit_state("openai") == "closed"


# ── Ledger extended fields ──────────────────────────────────────────

class TestLedgerExtendedFields:
    @pytest.mark.asyncio
    async def test_record_ok_has_extended_fields(self):
        from sqlalchemy.ext.asyncio import create_async_engine
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        ledger = UsageLedger(engine)
        resp = _ok_response()

        await ledger.record_ok(
            resp, "test request",
            workflow="report", operation="analyze",
            fallback_from="gemini", circuit_state="half-open",
            schema_retry=2,
        )

        from sqlalchemy import text
        async with engine.connect() as conn:
            rows = (await conn.execute(text("SELECT * FROM ai_usage"))).fetchall()
        assert len(rows) == 1
        row = rows[0]
        # id(0), ts(1), provider(2), model(3), status(4), input_tokens(5), output_tokens(6),
        # latency_ms(7), error(8), request_summary(9), workflow(10), operation(11),
        # fallback_from(12), fallback_to(13), circuit_state(14), schema_retry(15), success(16)
        assert row[2] == "openai"      # provider
        assert row[4] == "ok"          # status
        assert row[10] == "report"     # workflow
        assert row[11] == "analyze"    # operation
        assert row[12] == "gemini"     # fallback_from
        assert row[13] == "openai"     # fallback_to (== resp.provider)
        assert row[14] == "half-open"  # circuit_state
        assert row[15] == 2            # schema_retry
        assert row[16] == 1            # success (SQLite stores True as 1)

    @pytest.mark.asyncio
    async def test_record_error_has_extended_fields(self):
        from sqlalchemy.ext.asyncio import create_async_engine
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        ledger = UsageLedger(engine)

        await ledger.record_error(
            "gemini", "timeout", "connection timed out", "test",
            workflow="triage", operation="judge",
            fallback_from="openai", fallback_to="gemini",
            circuit_state="closed", schema_retry=0,
        )

        from sqlalchemy import text
        async with engine.connect() as conn:
            rows = (await conn.execute(text("SELECT * FROM ai_usage"))).fetchall()
        assert len(rows) == 1
        row = rows[0]
        assert row[2] == "gemini"      # provider
        assert row[4] == "timeout"     # status
        assert row[10] == "triage"     # workflow
        assert row[11] == "judge"      # operation
        assert row[12] == "openai"     # fallback_from
        assert row[14] == "closed"     # circuit_state
        assert row[15] == 0            # schema_retry
        assert row[16] == 0            # success (SQLite stores False as 0)


# ── UnifiedLLMClient fallback telemetry ──────────────────────────────

class TestLLMTelemetry:
    @pytest.mark.asyncio
    async def test_single_provider_ok_records_workflow(self):
        from sqlalchemy.ext.asyncio import create_async_engine
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        ledger = UsageLedger(engine)

        # RecordingProvider uses self.name="recording" as provider in response
        provider = RecordingProvider(outcomes=[_ok_response()])
        client = UnifiedLLMClient(
            providers={"recording": provider},
            chain=["recording"],
            ledger=ledger,
        )
        await client.generate(_req(), workflow="report", operation="analyze")

        from sqlalchemy import text
        async with engine.connect() as conn:
            rows = (await conn.execute(text("SELECT * FROM ai_usage"))).fetchall()
        assert len(rows) == 1
        row = rows[0]
        assert row[2] == "recording"   # provider
        assert row[10] == "report"     # workflow
        assert row[11] == "analyze"    # operation
        assert row[16] == 1            # success

    @pytest.mark.asyncio
    async def test_fallback_records_from_and_to(self):
        from sqlalchemy.ext.asyncio import create_async_engine
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        ledger = UsageLedger(engine)

        fail_provider = RecordingProvider(outcomes=[LLMUnavailable("recording", "nope")])
        ok_provider = RecordingProvider(outcomes=[_ok_response()])
        client = UnifiedLLMClient(
            providers={"fail": fail_provider, "ok": ok_provider},
            chain=["fail", "ok"],
            ledger=ledger,
        )
        await client.generate(_req(), workflow="triage", operation="judge")

        from sqlalchemy import text
        async with engine.connect() as conn:
            rows = (await conn.execute(text("SELECT * FROM ai_usage ORDER BY id"))).fetchall()
        assert len(rows) == 2

        # First row: failed provider (uses chain key "fail", not RecordingProvider.name)
        assert rows[0][2] == "fail"        # provider (chain key)
        assert rows[0][4] == "error"       # status
        assert rows[0][12] is None         # fallback_from (first in chain)
        assert rows[0][13] == "ok"         # fallback_to (next candidate via look-ahead)
        assert rows[0][16] == 0            # success

        # Second row: successful provider (RecordingProvider writes its .name to resp.provider)
        assert rows[1][2] == "recording"   # provider (RecordingProvider.name in LLMResponse)
        assert rows[1][4] == "ok"          # status
        assert rows[1][12] == "fail"       # fallback_from (chain key of failed provider)
        assert rows[1][16] == 1            # success

    @pytest.mark.asyncio
    async def test_schema_retry_recorded(self):
        from sqlalchemy.ext.asyncio import create_async_engine
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        ledger = UsageLedger(engine)

        # First call returns invalid JSON, second returns valid
        provider = RecordingProvider(outcomes=[
            "not json",
            '{"name": "test", "score": 0.5}',
        ])
        client = UnifiedLLMClient(
            providers={"recording": provider},
            chain=["recording"],
            ledger=ledger,
        )

        from pydantic import BaseModel
        class TestSchema(BaseModel):
            name: str
            score: float

        parsed, _ = await client.generate_structured(
            _req("classify this"), TestSchema,
            workflow="triage", operation="judge",
        )
        assert parsed.name == "test"

        from sqlalchemy import text
        async with engine.connect() as conn:
            rows = (await conn.execute(text("SELECT * FROM ai_usage ORDER BY id"))).fetchall()
        assert len(rows) == 2
        # First call: schema_retry=0
        assert rows[0][15] == 0
        # Second call: schema_retry=1
        assert rows[1][15] == 1

    @pytest.mark.asyncio
    async def test_aggregation_by_provider(self):
        """Verify we can aggregate logs by provider without extra instrumentation."""
        from sqlalchemy.ext.asyncio import create_async_engine
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        ledger = UsageLedger(engine)

        for _ in range(3):
            await ledger.record_ok(
                _ok_response("gemini", "3.6-flash"), "req",
                workflow="report", operation="analyze",
            )
        await ledger.record_error(
            "openai", "timeout", "timed out", "req",
            workflow="report", operation="analyze",
        )

        from sqlalchemy import text
        async with engine.connect() as conn:
            result = await conn.execute(text(
                "SELECT provider, COUNT(*) as calls, "
                "SUM(CASE WHEN success THEN 1 ELSE 0 END) as ok, "
                "SUM(CASE WHEN NOT success THEN 1 ELSE 0 END) as failed "
                "FROM ai_usage GROUP BY provider"
            ))
            rows = result.fetchall()

        agg = {r[0]: {"calls": r[1], "ok": r[2], "failed": r[3]} for r in rows}
        assert agg["gemini"]["calls"] == 3
        assert agg["gemini"]["ok"] == 3
        assert agg["gemini"]["failed"] == 0
        assert agg["openai"]["calls"] == 1
        assert agg["openai"]["ok"] == 0
        assert agg["openai"]["failed"] == 1
