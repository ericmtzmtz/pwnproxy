# Changelog

All notable changes to pwnproxy.

Format follows [Keep a Changelog](https://keepachangelog.com/).
Versions are not yet tagged; this file tracks work since the hardening cycle.

## Unreleased (0.2.0-dev)

### SQLi Status Differential

- **Detección de errores SQL mudos**: si un payload de error induce HTTP 5xx sobre un baseline 2xx (sin firma en el body — el error va a stderr, ej. bWAPP low `sqli_1.php`), el scanner emite `error-based`. Complementa la firma textual (que sigue dando `confirmed`).
- **Ladder conservador por defecto**: el 5xx sin firma se emite como `tentative/medium` (2+ payloads o 1 solo), porque un WAF/proxy/error-handler puede producir la misma firma HTTP sin SQL. `inferred/high` solo con `aggressive_status=True` (opt-in, ej. labs conocidos).
- **Guard anti-WAF**: antes de emitir por status differential, el stage (a) excluye 429/503/502 (rate-limit/bot-defense/bad gateway — antes `>=500` los contaba como triggers) y aborta el punto si >50% del barrido es respuesta de intermediario; (b) descarta si las respuestas 5xx parecen block page de WAF (denylist body+headers, `waf.py`); y (c) corre controles no-SQL (basura cruda + lookalikes de SQL válido que un WAF por patrón sí bloquearía) — si un control también 5xx, el cambio de status no es atribuible a SQL y no se emite finding.
- **Evidence cauta**: el finding del differential indica "control passed / no WAF block signature" y número de triggers, sin afirmar DBMS ni extracción de datos.

### SQLi Error-Based Baseline

- **Baseline check en `ErrorBasedStage`**: antes de probar payloads en un punto, se envía una request limpia; si la respuesta ya contiene una firma de error SQL (sesión/estado envenenado, ej. `session-input.php` guardando `1'`), el punto se omite — el error NO lo induce el parámetro. Elimina los falsos positivos `error-based confirmed` en Referer/User-Agent por sesión corrompida.

### Triage LLM Budget

- **Triage LLM: tentative nunca enqueue**: `skip_llm_if_confidence` (default `["tentative"]`) es un gate duro — los findings tentative se deciden solo por heurística y jamás consumen presupuesto LLM (cierra el rate-limit causado por la avalancha de SSRF FPs).
- **Modos**: `off` | `heuristic` (default, sin LLM) | `enrich` (LLM como enriquecimiento sobre confirmed/inferred, con `enrich_fp_threshold` para no tumbar a FP a la ligera) | `legacy_gray` (comportamiento viejo, opt-in).
- **Presupuesto por scan**: `max_llm_per_scan` (20) contado por `scan_id` (el scan tagea `extra.scan_id`); findings sin scan_id comparten el bucket "default".
- **`config.example.toml`**: sección `[triage]` documentada.

### DOM XSS Detection

#### Added
- **Detección de DOM XSS (estática)**: nueva etapa `DomStage` (corre en todos los depths, costo regex-only sobre la respuesta del probe) con dos señales:
  - **canary-in-sink**: el canary inyectado aparece dentro de una sink DOM en el script servido.
  - **param-reads-location**: el script lee el NOMBRE del parámetro desde `location.href/search/hash` (indexOf/split/substring) o `URLSearchParams.get()` y el mismo bloque escribe a una sink — patrón clásico DVWA xss_d donde el servidor NO refleja el valor.
- Sinks cubiertas: `document.write`, `innerHTML`/`outerHTML`/`insertAdjacentHTML`, `eval`/`Function`, `setTimeout`/`setInterval`, `location.href`/`assign`/`replace`, `window.open`, `document.location`. Emite `dom-xss` con `confidence="inferred"` y `severity="medium"` — sin ejecutar JS.
- **Anti-duplicado con reflected**: si el canary está en el HTML body, `ReflectedStage` lo cubre y `DomStage` no reporta.
- **`dom_sinks.py`**: matcher de sinks por regex con canary/param escapados, extensible a nuevas sinks.
- **Verificado en vivo**: el lab `xss_d` de DVWA ahora emite `dom-xss inferred` (sink `document.write`).

### SSRF Scanner Accuracy

#### Added
- **Confirmación OOB obligatoria**: el scanner SSRF solo reporta cuando el callback server recibe la petición del canary inyectado (evidencia real de que el servidor hizo una petición al callback). Un response HTTP (200/302/...) ya no cuenta como SSRF.
- **Filtro de parámetros URL-like**: solo se testean parámetros cuyo nombre sugiera URL/path (`url`, `uri`, `redirect`, `callback`, `file`, ...); se descartan `Referer`/`User-Agent` y parámetros genéricos (`name`, `id`, `default`).
- **Fail-closed**: si el callback server no está corriendo, el scanner no emite findings SSRF.
- **Fix `HTTPCallbackServer`**: al enlazar a puerto 0 (ephemeral), el puerto real ahora se propaga a `get_callback_url()` (antes devolvía `http://host:0/...` inalcanzable).

#### Removed
- **Técnica `ssrf-error-based`**: eliminada — reportaba cualquier response < 400 como SSRF, generando falsos positivos masivos en el auto-scan del proxy.

### Proxy Scope Enforcement

#### Added
- **Scope enforcement en persistencia**: `StorageAddon` acepta un `FlowFilter` opcional y descarta flows out-of-scope antes de escribir a `traffic.db` y de publicar `flow_stored`/`done` (el auto-scan ya no toca sitios fuera de scope). `HookRelayAddon` y el `BridgeRelay` del worker filtran request + response + error de forma consistente.
- **`FlowFilter.set_scope()`**: hot-swap del scope sin reconstruir addons; `reload_scope()` del worker y el `update_scope` de la API lo propagan en runtime (file-watch/Windows, signal/POSIX, y modo embedded).
- **Matcher por candidatos**: `ScopeConfig.is_in_scope` evalúa cada patrón contra `netloc` (`host:port`), hostname y URL completa. Un patrón bare `localhost:4280` ahora matchea su tráfico (antes no matcheaba nada).

#### Fixed
- **Scope era cosmético**: los flows out-of-scope (ej. telemetría de Chrome) seguían persistiéndose y auto-escanéándose; el único filtro existente vivía en el relay y con un `FlowFilter` stale (nunca recibía el scope recargado).
- **Patrón `host:port` no matcheaba**: `urlparse().hostname` no incluye el puerto y `fnmatch` es match completo, así que `localhost:4280` ni siquiera cubría el tráfico legítimo.

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

#### Scanner Accuracy
- **SQLi boolean-blind 4 rounds + baseline**: canonical pair first, escalation to extra pairs only when ambiguous, 4 consistency rounds (TRUE/FALSE/TRUE/FALSE) against a clean baseline before confirming.
- **Reflection vs XSS**: XSS scanner separates `reflected-xss` (confirmed exploitable breakout) from `unescaped-reflection` (low/`tentative`) via `ContextAnalyzer.is_exploitable`; CLI output now declares coverage scope.
- **`confidence` 3 levels**: `tentative` / `inferred` / `confirmed` carried through findings and TUI scanner screens.

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
