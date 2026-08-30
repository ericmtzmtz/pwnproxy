"""Structured logging and correlation for pwnproxy.

Usage::

    from pwnproxy.shared.observability import correlation_id, set_correlation_id, gen_correlation_id
    from pwnproxy.shared.observability import StructuredFormatter, timed, operation_context

    # Set up JSON logging
    handler = logging.StreamHandler()
    handler.setFormatter(StructuredFormatter())
    logging.root.addHandler(handler)
    logging.root.setLevel(logging.INFO)

    # Use in async code
    set_correlation_id(gen_correlation_id())
    with await operation_context("crawler", "fetch", job_id="j1"):
        await do_work()

    # Or as decorator
    @operation_context("scanner", "scan", finding_id="f1")
    async def scan_url(url: str): ...
"""

from __future__ import annotations

import contextlib
import json
import logging
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Callable, TypeVar

# ── correlation_id contextvar ───────────────────────────────────────

_correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")


def set_correlation_id(cid: str) -> None:
    """Set the current correlation ID (scoped to current task/thread)."""
    _correlation_id.set(cid)


def get_correlation_id() -> str:
    """Get the current correlation ID (empty string if unset)."""
    return _correlation_id.get()


def gen_correlation_id() -> str:
    """Generate a short unique correlation ID (8 hex chars)."""
    return uuid.uuid4().hex[:8]


# ── StructuredFormatter ────────────────────────────────────────────

class StructuredFormatter(logging.Formatter):
    """JSON log formatter with pwnproxy context fields.

    Every log record is a single JSON line with these fields:
    - timestamp, level, logger, message (standard)
    - correlation_id, job_id, session_id, component, operation
    - duration_ms, result, error_type (structured context)
    """

    def format(self, record: logging.LogRecord) -> str:
        # Extract structured fields from record (set via extra= or OperationContext)
        entry: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add correlation_id from contextvar if not in record
        cid = getattr(record, "correlation_id", None) or get_correlation_id()
        if cid:
            entry["correlation_id"] = cid

        # Add structured context fields if present
        for field_name in ("job_id", "session_id", "component", "operation", "duration_ms", "result", "error_type"):
            val = getattr(record, field_name, None)
            if val is not None:
                entry[field_name] = val

        # Exception info
        if record.exc_info and record.exc_info[1]:
            entry["exception"] = str(record.exc_info[1])
            entry["error_type"] = type(record.exc_info[1]).__name__

        return json.dumps(entry, default=str, ensure_ascii=False)


# ── Operation context manager ──────────────────────────────────────

@dataclass
class _OperationState:
    component: str
    operation: str
    job_id: str = ""
    session_id: str = ""
    start_time: float = 0.0
    result: str = "success"
    error_type: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


class OperationContext:
    """Async context manager that logs entry/exit of an operation with timing.

    Usage::

        async with OperationContext("crawler", "fetch", job_id="j1") as ctx:
            await fetch(url)
            # On success: logs result=success, duration_ms=...
            # On exception: logs result=failed, error_type=<exception class>

        # Or as a sync context manager (for non-async code)
        with OperationContext("api", "request", correlation_id="abc") as ctx:
            process_request()
    """

    def __init__(
        self,
        component: str,
        operation: str,
        job_id: str = "",
        session_id: str = "",
        correlation_id: str = "",
        **extra: Any,
    ) -> None:
        self._state = _OperationState(
            component=component,
            operation=operation,
            job_id=job_id,
            session_id=session_id,
            extra=extra,
        )
        self._cid_override = correlation_id
        self._logger = logging.getLogger(f"pwnproxy.{component}")

    async def __aenter__(self) -> OperationContext:
        self._state.start_time = time.monotonic()
        if self._cid_override:
            set_correlation_id(self._cid_override)
        self._logger.debug(
            "Starting %s",
            self._state.operation,
            extra={
                "component": self._state.component,
                "operation": self._state.operation,
                "job_id": self._state.job_id,
                "session_id": self._state.session_id,
            },
        )
        return self

    async def __aexit__(self, exc_type: type | None, exc_val: BaseException | None, exc_tb: Any) -> bool:
        duration_ms = round((time.monotonic() - self._state.start_time) * 1000, 1)
        if exc_val is not None:
            self._state.result = "failed"
            self._state.error_type = type(exc_val).__name__
        log_data = {
            "component": self._state.component,
            "operation": self._state.operation,
            "duration_ms": duration_ms,
            "result": self._state.result,
        }
        if self._state.job_id:
            log_data["job_id"] = self._state.job_id
        if self._state.session_id:
            log_data["session_id"] = self._state.session_id
        if self._state.error_type:
            log_data["error_type"] = self._state.error_type
        log_data.update(self._state.extra)

        if exc_val is not None:
            self._logger.error(
                "Completed %s in %.1fms: %s",
                self._state.operation, duration_ms, self._state.error_type,
                extra=log_data,
                exc_info=(exc_type, exc_val, exc_tb),
            )
        else:
            self._logger.info(
                "Completed %s in %.1fms",
                self._state.operation, duration_ms,
                extra=log_data,
            )
        return False  # Don't suppress exceptions

    def __enter__(self) -> OperationContext:
        self._state.start_time = time.monotonic()
        if self._cid_override:
            set_correlation_id(self._cid_override)
        return self

    def __exit__(self, exc_type: type | None, exc_val: BaseException | None, exc_tb: Any) -> bool:
        duration_ms = round((time.monotonic() - self._state.start_time) * 1000, 1)
        if exc_val is not None:
            self._state.result = "failed"
            self._state.error_type = type(exc_val).__name__
        log_data = {
            "component": self._state.component,
            "operation": self._state.operation,
            "duration_ms": duration_ms,
            "result": self._state.result,
        }
        if self._state.job_id:
            log_data["job_id"] = self._state.job_id
        if self._state.session_id:
            log_data["session_id"] = self._state.session_id
        if self._state.error_type:
            log_data["error_type"] = self._state.error_type
        log_data.update(self._state.extra)

        if exc_val is not None:
            self._logger.error(
                "Completed %s in %.1fms: %s",
                self._state.operation, duration_ms, self._state.error_type,
                extra=log_data,
                exc_info=(exc_type, exc_val, exc_tb),
            )
        else:
            self._logger.info(
                "Completed %s in %.1fms",
                self._state.operation, duration_ms,
                extra=log_data,
            )
        return False


def operation_context(
    component: str,
    operation: str,
    **kwargs: Any,
) -> OperationContext:
    """Factory that creates an OperationContext. Can be used as::

        async with operation_context("crawler", "fetch", job_id=jid) as ctx:
            ...

        with operation_context("api", "request") as ctx:
            ...
    """
    return OperationContext(component, operation, **kwargs)
