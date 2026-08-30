# Upgrade Guide — Hardening Cycle

Upgrading from pre-hardening to 0.2.0-dev (hardening cycle).

## Breaking Changes

### JobState Machine (Groups 3–4)

The `JobState` enum and transition rules are now enforced at the ORM level.
If you have custom code that calls `update_status()` directly on job storage:

- **Before**: arbitrary state strings (`"running"`, `"done"`, `"error"` — any string accepted).
- **After**: only legal transitions are accepted (`pending → queued → running → completed/failed/cancelled`). Illegal transitions raise `InvalidTransitionError` and are logged.

**Migration**: replace direct `update_status(status="done")` calls with the lifecycle API:

```python
from pwnproxy.services.jobs.lifecycle import JobLifecycle
await JobLifecycle.complete(job_id, result_summary=...)   # replaces update_status(status="done")
await JobLifecycle.fail(job_id, error_msg=...)            # replaces update_status(status="error")
await JobLifecycle.cancel(job_id)                         # replaces update_status(status="cancelled")
await JobLifecycle.mark_running(job_id)                   # replaces update_status(status="running")
```

### SessionManager.scope (Group 9.2)

The `scope` attribute on `SessionManager` is now mutated exclusively via `SessionManager.update_scope(data)`.
Direct assignment (`manager.scope = ScopeConfig(...)`) still works but won't persist or fire the change handler.

**Migration**: replace `manager.scope = new_scope; await manager.save()` with:

```python
await manager.update_scope({"in_scope": [...], "out_of_scope": [...]})
```

### Crawler Worker Internal API (Group 8)

`_run_crawl()`, `_run_bruteforce()`, `_publish_discovered()`, `_process_passive()` remain as backward-compat delegates on `CrawlerWorker`.
The canonical implementations are now in `services/crawler/strategies/` and `services/crawler/events.py`.

**Migration**: if you call these methods directly (unlikely outside tests), they still work. To use the new API:

```python
from pwnproxy.services.crawler.events import EventPublisher
from pwnproxy.services.crawler.strategies.active import run_crawl
```

No migration required for tests — backward-compat property bridges (`_stop_requested`, `_active_task`, `_active_job_id`, `_events`) handle old-style access.

---

## What Changed Internally (No Migration Required)

- **QoS-aware event queues**: `TcpBridgeServer` now drains topics in priority order on backpressure. No API change.
- **Telemetry ledger**: new columns on `usage` table (`workflow`, `operation`, `fallback_from`, `fallback_to`, `circuit_state`, `schema_retry`, `success`). Schema auto-migrates (SQLite additive only).
- **Observability**: structured JSON log lines now include `correlation_id`, `operation`, `status`. No API change; configure `StructuredFormatter` in your logging setup.
- **Plugin loader**: `_implicit_consumers()` deduplicated internally. No external API change.

---

## Post-Upgrade Verification

```bash
# Run the full test suite (628 tests, ~75s)
poetry run pytest tests/ -q

# Run golden workflows only
poetry run pytest tests/golden/ -m golden -v

# Run perf baseline (record)
poetry run pytest tests/perf/ -m perf --perf-record

# Run perf baseline (check)
poetry run pytest tests/perf/ -m perf --perf-check
```
