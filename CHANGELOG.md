# Changelog

All notable changes to pwnproxy.

Format follows [Keep a Changelog](https://keepachangelog.com/).
Versions are not yet tagged; this file tracks work since the hardening cycle.

## Unreleased (0.2.0-dev)

### Hardening Cycle (groups 1–9)

#### Added
- **JobState machine** (`shared/job_state.py`): atomic compare-and-swap transitions (`pending → queued → running → completed/failed/cancelled`); `transition_status()` enforces legal moves only; test: 5 atomic CAS tests.
- **JobLifecycle service** (`services/jobs/lifecycle.py`): single public entry point for all job state changes; emits structured log lines for audit trail; wires into scan, intruder, repeater, and crawler workers.
- **Observability** (`shared/observability.py`): `StructuredFormatter` for JSON log lines; `correlation_id` contextvar propagated via `OperationContext`; all endpoints tagged with trace ID.
- **QoS-aware bounded event queues** (`shared/bus/qos.py`, `shared/bus/transports/tcp_bridge.py`): per-client `QoSClassifiedQueue` with topics; `TcpBridgeServer` drains high/normal before low on backpressure; `TOPIC_QOS` mapping for all 15 topics.
- **Telemetry ledger** (`ai/llm/usage.py`): extended `UsageRecordORM` with `workflow`, `operation`, `fallback_from`, `fallback_to`, `circuit_state`, `schema_retry`, `success`; `CircuitBreaker.circuit_state()` exposes state; `UnifiedLLMClient.generate()` tracks fallback chain and schema retries; structured log lines on each call.
- **Crawler decomposition** (`services/crawler/`): `events.py` (EventPublisher with topic constants), `lifecycle.py` (CrawlStartConfig, BruteforceStartConfig), `strategies/passive.py` (extract_and_persist, process_passive), `strategies/active.py` (run_crawl with fetcher_cls param), `strategies/directory.py` (run_bruteforce with fetcher_cls param); `crawler_worker.py` slimmed to coordinator with backward-compat delegates + property bridges + `__getattr__`/`__setattr__` for test compat.
- **`_implicit_consumes(plugin)`** extracted in `plugins/core/loader.py` — deduplicates the 3-way call to `requires()` (load, start, activate).
- **`SessionManager.update_scope(data)`** — single scope write point (ownership matrix D1); router calls owner, keeps only component fan-out.
- **Performance baseline** (`tests/perf/test_perf_baseline.py`): opt-in `--perf-record/--perf-check`; in-process HTTP server, 30-page crawl; duration + max_rss (best-effort, Linux only); ×3 tolerance regression detector; baseline: 302ms, 19 pages.
- **17 golden workflow tests** (`tests/golden/`): deterministic E2E paths (scan, intrusive scan, crawl + scan, export) using FakeFetcher + FakeLLMClient; live verification sub-markers for bWAPP.
- **124+ crawler E2E tests**: BFS recursion, seed dedup, TLS verify, stop semantics, include_discovered, 409 conflict handling.

#### Fixed
- **TLS verify inverted**: `verify=self._ssl_insecure` → `verify=not self._ssl_insecure`; default flag changed to `False`.
- **BFS not recursing**: batch dequeue skipped all `depth > 0` entries already in `_visited` — seeds were the only ones ever fetched; removed incorrect dequeue check.
- **Seeds not marked visited**: back-links to seed path re-fetched on subsequent iterations; `__post_init__` now marks seeds.
- **Stop no longer publishes `crawl.failed`**: user-initiated stop flag prevents error toast in UI.
- **ExportEngine HTML template path** fix; LLM provider fallback failures now logged.

#### Changed
- **README repositioned as platform overview**; reference docs split to standalone files (ARCHITECTURE.md, docs/DOCS.md).
- **CrawlStats.maxed** field added to track `max_urls` cap in stats.

---

## Earlier (pre-hardening)

### Added
- Core mitmproxy-based HTTPS proxy engine with intercept workflow.
- Modular scanner architecture: SQLi, XSS, LFI, XXE, SSRF plugins.
- Plugin system: base classes, PluginLoader, PluginWatchdog, PyPI discovery, config.toml, CLI (install/list/search/create).
- Session management: create/resume/switch/isolate, scope persistence per session.
- Passive crawler: subprocess architecture, URL extraction, scope filtering, API + WebSocket + Dashboard.
- Active crawler: BFS engine, Fetcher (rate-limited), job storage, API, WebSocket events, Web UI.
- Directory bruteforce: builtin wordlists, soft-404 baseline detection, API/WebSocket/Web UI.
- Intruder: sniper mode, payload positions, concurrency, async task polling.
- Repeater: raw HTTP request sender, tab management, resizable split.
- Reports: AI report generation pipeline (LLM-powered).
- FP Triage: heuristic + LLM judge for gray-zone findings.
- Web UI (Astro + Preact + Tailwind v4): Dashboard, Proxy, Scanners, Repeater, Intruder, Reports, Scope, Settings.
- MCP server (pwnproxy-mcp/): scan_url, list_findings, get_status (FastMCP + JSON-RPC fallback).
- Docker deployment: backend + web UI containers, compose stack.
- REST API: `/plugins`, `/scan`, `/import/burp`, `/tasks`, `/sessions`, `/scope`, WebSocket endpoints.
- Command palette (Ctrl+K) in Web UI.
