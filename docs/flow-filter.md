# FlowFilter — Central Flow Authority

## Why

Each component (StorageAddon, InterceptorAddon, HookBus, scanners) independently
checks scope and capture status before processing a flow. As the system grows
(crawlers, exploiters, AI pipeline), every new component must re-implement the
same checks — duplicated logic, inconsistent behavior, maintenance burden.

**Design goal:** A single `FlowFilter` that all components query. Deciding whether
a flow should be processed happens once, at the entry point.

## Current State (before FlowFilter)

```
BridgeRelay.response() ──→ TcpBridge ──→ HookBus ──→ Scanners
  │                                              (no check)
  └── StorageAddon.response()
        ├── capture_enabled?         ← checkpoint 1
        ├── scope_filter?            ← checkpoint 2
        └── persist to DB

InterceptorAddon.request()
  ├── enabled?                       ← checkpoint 3
  └── scope_filter?                  ← checkpoint 4 (lambda propio)

HookBus.publish()
  └── scope_filter?                  ← checkpoint 5 (solo request/response/error/flow)
```

**Problems:**
- 5 independent checkpoints, all reading the same `ScopeConfig`
- Each new component must re-implement the same logic
- Scanners have NO filter (receive all flows regardless of scope/capture)
- Capture toggle only affects StorageAddon, not scanners
- Interceptor has its own lambda, separate from the rest

## Target State (with FlowFilter)

```
                    ┌───────────────────────┐
                    │     FlowFilter         │
                    │                        │
                    │  .allow(url) → bool    │
                    │  .capture_enabled      │
                    │  .scope (ScopeConfig)  │
                    └──────────┬────────────┘
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                    │
          ▼                    ▼                    ▼
   ┌────────────┐      ┌──────────────┐      ┌──────────────┐
   │ BridgeRelay│      │ StorageAddon │      │ Interceptor  │
   │ (subproc)  │      │              │      │              │
   │ filtra     │      │ SIN filtro   │      │ usa          │
   │ antes de   │      │ propio       │      │ FlowFilter   │
   │ publicar   │      │ recibe flows │      │ en vez de    │
   │ al bridge  │      │ ya filtrados │      │ lambda propio│
   └────────────┘      └──────────────┘      └──────────────┘
                              │
                              ▼
                      ┌──────────────┐
                      │   HookBus    │
                      │ SIN filtro   │
                      │ scope propio │
                      │ (ya filtra   │
                      │  BridgeRelay)│
                      └──────┬───────┘
                             │
               ┌─────────────┼─────────────┐
               │             │             │
               ▼             ▼             ▼
         ┌──────────┐ ┌──────────┐ ┌──────────┐
         │ Scanners │ │ Crawler  │ │Exploiter │
         │          │ │ (futuro) │ │ (futuro) │
         └──────────┘ └──────────┘ └──────────┘
```

## FlowFilter API

```python
# pwnproxy/shared/flow_filter.py

class FlowFilter:
    """Single authority: should this flow be processed by ANY component?
    
    All components (BridgeRelay, StorageAddon, InterceptorAddon, HookBus,
    scanners, future crawlers/exploiters) query this one service.
    """

    def __init__(self, scope_config: ScopeConfig):
        self._scope = scope_config
        self._capture_enabled = True

    def allow(self, url: str) -> bool:
        """Central decision for ALL components.
        
        Returns False when:
        1. Capture is disabled (paused)
        2. URL is out of scope (scope enabled + no matching pattern)
        
        All consumers MUST call this before processing a flow.
        """
        if not self._capture_enabled:
            return False
        return self._scope.is_in_scope(url)

    @property
    def capture_enabled(self) -> bool:
        return self._capture_enabled

    def set_capture_enabled(self, enabled: bool) -> None:
        self._capture_enabled = enabled
```

## Integration Points

### 1. BridgeRelay (proxy_worker.py) — PRIMARY FILTER

```python
class BridgeRelay:
    def __init__(self, bridge, flow_filter: FlowFilter):
        self._bridge = bridge
        self._flow_filter = flow_filter

    def response(self, f):
        if not self._flow_filter.allow(f.request.pretty_url):
            return  # ← ni publica, ni persiste, ni escanea
        flow = Flow.from_mitmproxy(f)
        asyncio.create_task(self._bridge.publish("proxy.flow", flow.to_dict()))
```

This single check at the entry point eliminates the need for filters downstream.
StorageAddon, scanners, interceptors, future components — all receive only
pre-filtered flows.

### 2. StorageAddon (storage.py) — REMOVE OWN CHECKS

```python
class StorageAddon:
    def __init__(self, db_engine, hook_bus=None, capture_enabled_fn=None):
        # REMOVED: scope_filter parameter — flows are pre-filtered
        # REMOVED: capture_enabled_fn — handled by FlowFilter upstream
        self.db_engine = db_engine
        self.hook_bus = hook_bus
        ...

    def response(self, f):
        # REMOVED: capture_enabled_fn check
        # REMOVED: scope_filter check
        # Flow already passed FlowFilter in BridgeRelay
        pwn_flow = Flow.from_mitmproxy(f)
        task = asyncio.create_task(self._store_flow(pwn_flow))
        ...
```

**Exception:** When StorageAddon runs in embedded mode (ProxyEngine) without
BridgeRelay, it MAY receive a `flow_filter` to check itself.

### 3. InterceptorAddon (interceptor/addon.py) — USE FLOWFILTER

```python
class InterceptorAddon:
    def __init__(self, output_queue, flow_filter: FlowFilter):
        self._flow_filter = flow_filter
        ...

    def request(self, f):
        if not self._enabled:
            return
        if not self._flow_filter.allow(f.request.pretty_url):
            return
        f.intercept()
        ...
```

### 4. HookBus (hooks.py) — REMOVE SCOPE FILTER

```python
class HookBus:
    # REMOVED: _scope_filter — no longer needed, flows are pre-filtered
    # REMOVED: set_scope_filter() — same reason
    # Filtered channels set can be removed since all flows pass
```

### 5. ProyEngine (engine.py) — SIMPLIFIED

```python
class ProxyEngine:
    # REMOVED: scope_filter parameter
    # Uses FlowFilter internally
    def __init__(self, hook_bus, db_engine=None, ..., flow_filter=None):
        self._flow_filter = flow_filter
        ...
```

## FlowFilter Lifecycle

```
1. SessionManager creates ScopeConfig (from scope.json on disk)
2. start.py creates FlowFilter(SessionManager.scope)
3. FlowFilter passed to:
   - ProxyEngine (→ ProxyWorker → BridgeRelay)
   - InterceptorAddon
4. PUT /proxy/toggle → FlowFilter.set_capture_enabled()
5. PUT /sessions/scope → updates SessionManager.scope
   → FlowFilter reads it via reference (same ScopeConfig object)
6. POST /flows/{id}/outscope → mutates SessionManager.scope.out_of_scope
   → FlowFilter reads it automatically
```

## Migration Steps

### Phase 1: Create FlowFilter + BridgeRelay integration
1. Create `pwnproxy/shared/flow_filter.py` with `FlowFilter` class
2. Wire in `ProxyWorker.__init__()` and pass to `BridgeRelay`
3. Add `allow()` check in `BridgeRelay.response()`
4. Keep existing StorageAddon/Interceptor checks temporarily (belt + suspenders)

### Phase 2: Remove legacy checks
5. Remove `scope_filter` from `StorageAddon.__init__()` and `response()`
6. Remove `scope_filter` from `HookBus.__init__()` and `publish()`
7. Replace `InterceptorAddon` lambda with `FlowFilter` reference
8. Remove `scope_filter` from `ProxyEngine.__init__()` and `configure()`
9. Clean up `start.py` - remove lambda scope_check/hook_bus.set_scope_filter

### Phase 3: Cleanup
10. Remove `ProxyProcess.send_scope_update()` if FlowFilter reads live ScopeConfig
11. Remove `reload_scope()` from ProxyWorker (no longer needed)
12. Update tests
13. Update docs

## Finding Request Headers

### Problem

The `Finding` dataclass does not store original request headers. When "Send to
Repeater" is triggered from FindingsTable or ScannersPage, the raw_request is
built from minimal data (method, path, URL) — no original headers, no body.

### Solution: Add request metadata to Finding

```python
# pwnproxy/plugins/core/base.py

@dataclass
class Finding:
    scanner: str
    url: str
    method: str
    # ... existing fields ...
    extra: dict = field(default_factory=dict)
    # NEW: request_headers and request_body stored in extra
    # extra["request_headers"] = {"Host": "example.com", ...}
    # extra["request_body"] = "param=value"
```

**Why `extra`:** No DB migration needed — `FindingORM.extra` is already a
JSON column. The frontend reads `finding.extra.request_headers` instead of
the non-existent `finding.request.headers`.

### Scanner changes

```python
# In each ScannerPlugin.on_flow(flow):
async def on_flow(self, flow):
    points = extract_params(flow)
    for point in points:
        async for finding in self._scanner._scan_point(point):
            finding.extra["request_headers"] = flow.request_headers
            finding.extra["request_body"] = flow.request_body
            yield finding
```

This is inside each scanner's `on_flow`. Alternatively, do it once in the
PluginLoader after the scanner yields:

```python
# UniversalPluginLoader._handle_flow()
async for result in plugin.on_flow(flow):
    if isinstance(result, Finding) and "request_headers" not in result.extra:
        result.extra["request_headers"] = flow.request_headers
        result.extra["request_body"] = flow.request_body
    await self._publish_results(plugin, result)
```

The **loader-level approach** is better — one change covers all scanners.

### Frontend changes

```typescript
// FindingsTable.tsx — replace:
//   finding.request.headers  (undefined)
// With:
//   finding.extra?.request_headers ?? {}

// ScannersPage.tsx — same pattern
```

## Open Questions

1. **Subprocess communication:** The BridgeRelay lives in the proxy subprocess.
   How does FlowFilter.get_capture_enabled() update when toggled from API?
   - Option A: Send signal (SIGUSR1) with new state
   - Option B: FlowFilter in subprocess polls a shared file
   - Option C: Pass capture_enabled via existing TcpBridge event

2. **Backward compatibility:** Existing plugins may call
   `hook_bus.set_scope_filter()`. Deprecate gracefully or break?

3. **HookBus filtering:** If BridgeRelay filters at source, can we remove
   HookBus._scope_filter entirely? Yes — it becomes dead code.

## References

- `pwnproxy/shared/hooks.py` — HookBus (will remove _scope_filter)
- `pwnproxy/services/proxy/addons/storage.py` — StorageAddon (will remove checks)
- `pwnproxy/services/proxy/proxy_worker.py` — BridgeRelay (primary filter point)
- `pwnproxy/services/proxy/interceptor/addon.py` — InterceptorAddon
- `pwnproxy/services/proxy/engine.py` — ProxyEngine
- `pwnproxy/plugins/core/base.py` — Finding dataclass
- `pwnproxy/plugins/core/loader.py` — UniversalPluginLoader._handle_flow
- `pwnproxy/services/session/manager.py` — ScopeConfig
- `pwnproxy/transport/rest/proxy.py` — /proxy/toggle endpoint
- `docs/message-bus.md` — existing architecture doc
```