"""Tests for observability: StructuredFormatter, correlation_id, OperationContext."""

import asyncio
import json
import logging

import pytest

from pwnproxy.shared.observability import (
    OperationContext,
    StructuredFormatter,
    gen_correlation_id,
    get_correlation_id,
    operation_context,
    set_correlation_id,
)


# ── correlation_id contextvar ───────────────────────────────────────

class TestCorrelationId:
    def test_default_empty(self):
        """Default correlation_id is empty string."""
        # Reset contextvar for this test
        set_correlation_id("")
        assert get_correlation_id() == ""

    def test_set_and_get(self):
        cid = gen_correlation_id()
        set_correlation_id(cid)
        assert get_correlation_id() == cid

    def test_gen_correlation_id_unique(self):
        ids = {gen_correlation_id() for _ in range(100)}
        assert len(ids) == 100  # all unique

    def test_gen_correlation_id_length(self):
        cid = gen_correlation_id()
        assert len(cid) == 8
        assert all(c in "0123456789abcdef" for c in cid)

    @pytest.mark.asyncio
    async def test_correlation_id_per_task(self):
        """Different asyncio tasks get independent correlation IDs."""
        results = {}

        async def worker(name: str, cid: str):
            set_correlation_id(cid)
            await asyncio.sleep(0.01)
            results[name] = get_correlation_id()

        t1 = asyncio.create_task(worker("a", "cid_aaaa"))
        t2 = asyncio.create_task(worker("b", "cid_bbbb"))
        await asyncio.gather(t1, t2)

        assert results["a"] == "cid_aaaa"
        assert results["b"] == "cid_bbbb"


# ── StructuredFormatter ─────────────────────────────────────────────

class TestStructuredFormatter:
    def _make_record(
        self,
        msg: str = "test",
        level: int = logging.INFO,
        name: str = "pwnproxy.test",
        **extra,
    ) -> logging.LogRecord:
        record = logging.LogRecord(
            name=name, level=level, pathname="", lineno=0,
            msg=msg, args=(), exc_info=None,
        )
        for k, v in extra.items():
            setattr(record, k, v)
        return record

    def test_basic_fields(self):
        formatter = StructuredFormatter()
        record = self._make_record("hello world")
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["message"] == "hello world"
        assert parsed["level"] == "INFO"
        assert parsed["logger"] == "pwnproxy.test"
        assert "timestamp" in parsed

    def test_structured_context_fields(self):
        formatter = StructuredFormatter()
        record = self._make_record(
            "fetch failed",
            job_id="j42",
            component="crawler",
            operation="fetch",
            duration_ms=123.4,
            result="failed",
            error_type="TimeoutError",
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["job_id"] == "j42"
        assert parsed["component"] == "crawler"
        assert parsed["operation"] == "fetch"
        assert parsed["duration_ms"] == 123.4
        assert parsed["result"] == "failed"
        assert parsed["error_type"] == "TimeoutError"

    def test_correlation_id_from_contextvar(self):
        formatter = StructuredFormatter()
        set_correlation_id("test_corr_123")
        record = self._make_record("with correlation")
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["correlation_id"] == "test_corr_123"

    def test_correlation_id_from_record(self):
        """Record-level correlation_id overrides contextvar."""
        formatter = StructuredFormatter()
        set_correlation_id("ctx_var_cid")
        record = self._make_record("record cid", correlation_id="record_cid")
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["correlation_id"] == "record_cid"

    def test_exception_adds_error_type(self):
        formatter = StructuredFormatter()
        try:
            raise ValueError("bad value")
        except ValueError:
            import sys
            record = self._make_record("error", exc_info=sys.exc_info())
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["error_type"] == "ValueError"
        assert "bad value" in parsed["exception"]

    def test_no_extra_fields_when_absent(self):
        """Fields not set should not appear in output."""
        formatter = StructuredFormatter()
        record = self._make_record("clean")
        output = formatter.format(record)
        parsed = json.loads(output)
        assert "job_id" not in parsed
        assert "duration_ms" not in parsed
        assert "error_type" not in parsed


# ── OperationContext ─────────────────────────────────────────────────

class TestOperationContext:
    @pytest.mark.asyncio
    async def test_success_logs_result(self, caplog):
        with caplog.at_level(logging.INFO, logger="pwnproxy.test"):
            async with OperationContext("test", "op1") as ctx:
                pass
        assert any("Completed op1" in r.message for r in caplog.records)
        # Find the completion record
        completion = [r for r in caplog.records if "Completed op1" in r.message]
        assert len(completion) == 1
        assert getattr(completion[0], "result", None) == "success"
        assert getattr(completion[0], "duration_ms", None) is not None
        assert getattr(completion[0], "duration_ms", 0) >= 0

    @pytest.mark.asyncio
    async def test_failure_logs_error_type(self, caplog):
        with caplog.at_level(logging.ERROR, logger="pwnproxy.test"):
            try:
                async with OperationContext("test", "op_fail"):
                    raise ConnectionError("refused")
            except ConnectionError:
                pass
        failure = [r for r in caplog.records if "Completed op_fail" in r.message]
        assert len(failure) == 1
        assert getattr(failure[0], "result", None) == "failed"
        assert getattr(failure[0], "error_type", None) == "ConnectionError"

    @pytest.mark.asyncio
    async def test_job_id_in_log(self, caplog):
        with caplog.at_level(logging.INFO, logger="pwnproxy.test"):
            async with OperationContext("test", "op2", job_id="j99"):
                pass
        completion = [r for r in caplog.records if "Completed op2" in r.message]
        assert len(completion) == 1
        assert getattr(completion[0], "job_id", None) == "j99"

    @pytest.mark.asyncio
    async def test_sets_correlation_id(self):
        cid = gen_correlation_id()
        async with OperationContext("test", "op3", correlation_id=cid):
            assert get_correlation_id() == cid

    def test_sync_context_manager(self, caplog):
        with caplog.at_level(logging.INFO, logger="pwnproxy.test"):
            with OperationContext("test", "sync_op"):
                pass
        completion = [r for r in caplog.records if "Completed sync_op" in r.message]
        assert len(completion) == 1
        assert getattr(completion[0], "result", None) == "success"


# ── Integration: correlated operations share correlation_id ──────────

class TestCorrelationIntegration:
    @pytest.mark.asyncio
    async def test_same_request_shares_correlation_id(self, caplog):
        """Multiple operations within same context share correlation_id."""
        cid = "req_abc12345"
        set_correlation_id(cid)

        with caplog.at_level(logging.INFO, logger="pwnproxy.crawler"):
            async with OperationContext("crawler", "fetch", job_id="j1"):
                async with OperationContext("crawler", "parse"):
                    pass

        # Both operations should have the same correlation_id in their logs
        for record in caplog.records:
            if hasattr(record, "correlation_id") and record.correlation_id:
                assert record.correlation_id == cid

    @pytest.mark.asyncio
    async def test_different_requests_different_correlation_ids(self):
        """Two independent operations get different correlation_ids."""
        results = []

        async def do_op(name: str, cid: str):
            set_correlation_id(cid)
            async with OperationContext("test", name):
                results.append((name, get_correlation_id()))

        await asyncio.gather(
            do_op("op_a", "cid_0001"),
            do_op("op_b", "cid_0002"),
        )

        a_cid = next(c for n, c in results if n == "op_a")
        b_cid = next(c for n, c in results if n == "op_b")
        assert a_cid == "cid_0001"
        assert b_cid == "cid_0002"
