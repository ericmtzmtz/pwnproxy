# Plugin Architecture

**Status:** normative. This file is the **source of truth** for how pwnproxy plugins
work and how they MUST be built. When code and this document disagree, the document
states the target: either fix the code, or open an OpenSpec change to amend this doc.

Where the current implementation does **not** yet conform, it is listed explicitly in
[§12 Conformance status](#12-conformance-status). That section doubles as the fix
checklist and is tracked by the branch `fix/scanner-depth-integrity`.

---

## 1. Scope and principles

A plugin is a self-contained unit that consumes and produces data contracts through the
loader and the message bus. The architecture is governed by four rules:

1. **Single writer per state.** Runtime configuration is owned by the loader; the
   message bus owns routing; findings and flows have exactly one owner. See
   `docs/ownership-matrix.md`.
2. **Config is injected at load time, never read from globals.** A plugin receives its
   configuration through `PluginContext.config` during `on_load()`. It MUST NOT read
   environment variables, `~/.pwnproxy/config.toml`, or module-level globals directly.
3. **Data is injected, not imported by shared code.** Scanner-specific data (signatures,
   payloads) is defined in the plugin package and passed into stages via constructors.
   `shared/` MUST NOT import `plugins/`.
4. **The path used in production is the path used in tests.** Integration tests MUST
   exercise the real loader. Constructing plugin state directly in a test to "make it
   pass" is forbidden (see [§14](#14-testing-requirements-the-gate)).

---

## 2. Plugin types

| Type | Consumes | Produces | Entry point |
|---|---|---|---|
| `ScannerPlugin` | `flow` | `finding` | `on_flow(flow) -> AsyncGenerator[Finding, None]` |
| `HookPlugin` | — | — | `on_request(flow) -> Flow`, `on_response(flow) -> Flow` |
| Flow consumer | `flow` | any | `on_flow(flow)` |
| Finding consumer | `finding` | any | `on_finding(finding)` |
| Surface consumer | `surface` | any | `on_surface(surface)` |
| Evidence consumer | `evidence` | any | `on_evidence(evidence)` |

Base classes and mixins:

- `PwnPlugin` — lifecycle base (`on_load`, `on_unload`, `metadata`, `context`).
  `pwnproxy/plugins/core/base.py:85`
- `ScannerPlugin` — `PwnPlugin` + `FlowConsumer`; `category="scanner"`.
  `pwnproxy/plugins/core/base.py:100`
- Consumer mixins (`FlowConsumer`, `FindingConsumer`, `SurfaceConsumer`,
  `EvidenceConsumer`) — duck-typing contracts in
  `pwnproxy/plugins/core/contracts.py`.

Only `ScannerPlugin` is load-bearing today. The other mixins define the forward-looking
contract; do not invent new consumption channels without an OpenSpec change.

---

## 3. Core data contracts

### 3.1 `PluginMetadata`

Defined in `pwnproxy/plugins/core/base.py:18`:

```python
@dataclass
class PluginMetadata:
    name: str                       # REQUIRED, unique, kebab-case
    version: str                    # REQUIRED, semver
    author: str = ""
    category: str = ""              # "scanner" | "hook" | ...
    description: str = ""
    disabled: bool = False          # runtime enable/disable state
    parameters: dict = {}           # self-describing parameter schema (AI discovery)
    capabilities: list[str] = []
    examples: list[dict] = []
    consumes: list[str] = []        # e.g. ["flow"]
    produces: list[str] = []        # e.g. ["finding"]
    storage: type | None = None
```

Required for every plugin: `name`, `version`, `category`, `description`, `consumes`,
`produces`. Recommended: `capabilities`, `parameters`, `examples`.

`parameters` is a self-describing schema, not code. It lets agents and the Web UI
discover what a plugin accepts without reading source. Each entry:

```python
parameters = {
    "detection_depth": {
        "type": "string",              # string | integer | float | boolean | array
        "required": False,
        "default": "fast",
        "choices": ["fast", "standard", "deep"],
        "description": "Detection thoroughness ceiling",
    },
}
```

> The `parameters` block describes the **scan-run configuration** consumed via
> `PluginContext.config` (see [§3.2](#32-plugincontext-and-the-configuration-contract)).
> It MUST stay in sync with the keys the plugin actually reads.

A scanner MAY also declare class-level `techniques: list[str]` (the technique values it
emits) and `capabilities: list[str]`. `techniques` is validated against
`capabilities` by tests; it is not part of `PluginMetadata`.

### 3.2 `PluginContext` and the configuration contract

```python
@dataclass
class PluginContext:
    config: dict = field(default_factory=dict)
    hook_bus: Any = None
    def update(self, **overrides) -> None: ...   # merges, never replaces
```

**Normative config contract**

- A plugin reads **all** runtime configuration from `self.context.config` **inside
  `on_load()`**, once.
- The **loader** is the only component that populates `config`, via
  `PluginContext(config=<resolved scan config>)` at load time.
- `on_flow(flow)` takes **only** the flow. Depth, evasion, and every other knob are
  **load-time** properties baked into the chain at `on_load()`; they MUST NOT be
  parameters of `on_flow` and MUST NOT be changed per flow.
- A plugin MUST NOT read config lazily at scan time, from the environment, or from a
  global. One owner, one load-time snapshot.

**Standard keys** (all optional; a plugin MUST provide the default shown):

| Key | Type | Values | Default | Applies to |
|---|---|---|---|---|
| `depth` | str | `fast` \| `standard` \| `deep` | `fast` | all scanners |
| `evasion_level` | str | `none` \| `light` \| `aggressive` | `none` | all scanners |
| `aggressive_status` | bool | — | `False` | SQLi |
| `callback_host` | str | — | `127.0.0.1` | SSRF / OOB |
| `callback_port` | int | — | `18080` | SSRF / OOB |

- The `scanners` allow-list is **not** a plugin concern: the caller decides which plugin
  classes to load. A plugin never filters itself out.
- Unknown keys are ignored; a plugin MUST NOT crash on extra keys.
- Invalid values (e.g. `depth="turbo"`) MUST fail **at load time** with a configuration
  error — never mid-scan.

**Loader API (target contract)**

```python
# Load-time config injection. config=None => {} (test / legacy default).
await loader.load_builtin(plugin_instance, config={"depth": "standard", "evasion_level": "light"})
await plugin.on_load()          # reads self.context.config here
```

`UniversalPluginLoader.load()` registers the plugin and its channels but does **not** set
`context`. `load_builtin()` is the config-aware primitive: it registers, sets
`PluginContext(config=...)`, then calls `on_load()`.

`run_scan()` runs the loaded plugins over a flow and takes **only** the flow: depth and
evasion were already resolved at load time.

### 3.3 `Finding`

Defined in `pwnproxy/plugins/core/base.py:43`. Every scanner MUST emit fully populated
`Finding` objects:

| Field | Type | Notes |
|---|---|---|
| `scanner` | str | plugin `name` |
| `url` | str | target URL |
| `method` | str | HTTP method |
| `param_name` | str | injected parameter |
| `param_location` | str | `query` \| `body` \| `cookie` \| `header` |
| `technique` | str | see vocabulary below |
| `severity` | str | `low` \| `medium` \| `high` \| `critical` |
| `confidence` | str | `tentative` \| `inferred` \| `confirmed` |
| `payload` | str | payload that triggered it |
| `evidence` | str | human-readable reason |
| `timestamp` | datetime | UTC (auto) |
| `extra` | dict | scanner metadata (`scan_id`, etc.) |
| `request_data` | dict \| None | serialized triggering request |

**Confidence scale (three levels, normative):**

- `tentative` — weak signal (e.g. unescaped reflection with no exploit). Never
  exploitable by itself. The triage LLM judge is **never** invoked for this level.
- `inferred` — deterministic differential across stable rounds (e.g. boolean-blind
  TRUE vs FALSE) but no observed execution.
- `confirmed` — the payload demonstrably took effect (SQL error surfaced, XSS breakout,
  OOB callback).

**Technique vocabulary (recommended):** `error-based`, `boolean-blind`, `time-based`,
`oob`, `reflected`, `stored`, `dom-based`, `path-traversal`, `command-injection`,
`code-injection`, `template-injection`.

**Evidence** MUST be a human-readable string with concrete values, e.g.
`"Response length diff: TRUE=246, FALSE=158 (diff=88)"`.

---

## 4. Lifecycle

```
discover/construct                 load_builtin(plugin, config)
        │                                   │
        ▼                                   ▼
   plugin instance ────────────────▶ load()          registers plugin + channels
                                          │
                                          ├─ plugin.context = PluginContext(config=config)
                                          └─ await plugin.on_load()      build chain, replayer
                                                          │
                                    loader.start() ───────┴──▶ spawn consumer tasks (bus channels)
                                                          │
                              per incoming flow ──────────▶ await plugin.on_flow(flow)
                                                          │
                                    loader.unload() ──────┴──▶ cancel tasks, await plugin.on_unload()
```

1. **Load** — `load_builtin(plugin, config)` → `load()` + set context + `on_load()`.
   The plugin builds its `DetectionChain` and long-lived resources (e.g.
   `RequestReplayer`) here.
2. **Start** — `loader.start()` spawns one consumer task per consumed channel.
3. **Scan** — each flow reaches `plugin.on_flow(flow)`; the plugin extracts injection
   points and delegates to the **already built** chain.
4. **Unload** — `loader.unload()` cancels tasks, calls `on_unload()` (close the
   replayer), and removes the plugin.

Exactly one instance of a plugin exists at a time. All resources opened in `on_load()`
MUST be released in `on_unload()`.

---

## 5. Scanner data flow

```
flow (from bus)
  └─ extract(flow)                      pwnproxy/shared/scan/params.py:54
       → list[InjectionPoint]           query, body (form/json/xml), cookie, header
  └─ dedup by (host+path, name, location)
  └─ for each point: scanner._scan_point(point)
       └─ chain.run(flow, [point])
            └─ stages in order (cheapest first), confirmed points skipped
                 └─ replayer.replay(point, payload, evasion_level)
                      └─ inspect response → StageResult(findings, confirmed_points)
```

`InjectionPoint` (`shared/scan/params.py:37`) is the single type used everywhere. Its
`key` property is `(method, host+path, name, location)` and drives cross-stage dedup.

---

## 6. Detection chains and depth semantics

`pwnproxy/plugins/core/chain.py`.

```python
class DetectionDepth(str, Enum):
    FAST = "fast"; STANDARD = "standard"; DEEP = "deep"   # FAST < STANDARD < DEEP
```

**Normative depth semantics**

- `depth` is a **ceiling** (maximum thoroughness), **not** a starting point.
- A chain **always starts at the cheapest stages** and escalates toward the ceiling as
  budget allows. It MUST NOT skip a cheaper stage because a higher depth was requested.
- Stage selection is **monotonic**: a stage with `min_depth <= depth` runs.

Two chain implementations:

**`DetectionChain`** — fixed set of stages, no escalation:

```python
class DetectionChain:
    def __init__(self, stages, depth=DetectionDepth.FAST): ...
    async def run(self, flow, points) -> AsyncGenerator[Finding, None]:
        # runs every stage with stage.should_run(depth); confirmed points skipped
```

Use it when there is no budget concern (XSS, SSRF, XXE, command-injection today).

**`BudgetChain`** — escalates FAST → STANDARD → DEEP up to the ceiling, bounded by **one
total time budget for the entire chain**:

```python
BudgetChain(stages, depth=<ceiling>, max_depth=DEEP, budget_ms=...)
```

- `budget_ms` is the budget for the **whole chain**, not per wave. (The attribute name
  `WAVE_BUDGET_MS` is misleading and slated for rename; see §12.)
- Waves run cheapest-first. Escalation is not gated by a "floor": the ceiling is what
  limits how deep the chain may go.
- The chain sets an absolute deadline (`start + budget`) on every stage via
  `stage.set_deadline(deadline)`.

Use it for expensive escalations (SQLi, LFI today).

**Factory**

```python
chain_from_depth(stages, depth="standard", budget_ms=None)
# -> BudgetChain starting at FAST, ceiling = depth, budget tiered by depth
```

**Construction-time errors**: an invalid `depth` string MUST raise a configuration error
at plugin load time.

---

## 7. Stages

`DetectionStage` (`pwnproxy/plugins/core/chain.py:44`). Contract:

```python
class DetectionStage(ABC):
    order: int = 0                                   # lower runs first
    min_depth: DetectionDepth = DetectionDepth.FAST  # ceiling required to run
    capability: str = ""

    def __init__(self, replayer, <injected data>, evasion_level="none"): ...

    @abstractmethod
    async def execute(self, flow, injection_points) -> StageResult: ...

    def set_deadline(self, deadline: float | None) -> None: ...  # override if you loop
```

Normative requirements:

- **Constructor injection**: stages receive signatures/payloads/evasion. They MUST NOT
  import scanner-specific module-level data (`shared/` must not depend on `plugins/`).
- **`StageResult`**: `findings` (list) and `confirmed_points` (set of `InjectionPoint.key`).
  Later stages skip confirmed points.
- **Deadlines**: a stage that loops over multiple payloads/points over the network MUST
  override `set_deadline()` and stop early once the absolute deadline passes. The default
  is a no-op, so an unbudgeted loop can overrun the chain budget.
- **Errors**: wrap risky logic so a stage failure yields an empty `StageResult`; never
  abort the chain.

```python
@dataclass
class StageResult:
    findings: list[Finding] = field(default_factory=list)
    confirmed_points: set[tuple] = field(default_factory=set)
```

---

## 8. Replayer and evasion

`RequestReplayer` (`pwnproxy/shared/scan/replayer.py:15`) owns HTTP I/O and rate limiting.

```python
replayer = RequestReplayer()                       # created once in on_load()
await replayer.replay(point, payload, timeout=5.0, evasion_level="none")
replayer.build_payload_request(point, payload, evasion_level)  # build, don't send
await replayer.send_clean(point)                   # untouched baseline
await replayer.close()                             # in on_unload()
```

- Shared global semaphore (5), per-host semaphore (2), and a fixed inter-request delay.
  Do **not** add per-scanner timers; use the shared replayer.
- Injection is location-aware: query (URL re-encode), form body, JSON body (with type
  coercion), cookie, header.
- Subclass `_build_request()` only for protocol-specific mutation (see `XxeReplayer` in
  `pwnproxy/shared/scan/replayers/xxe.py`).

**Evasion** (`pwnproxy/shared/scan/evasion.py:13`):

| Level | Transform |
|---|---|
| `none` | no change |
| `light` | double URL-encode |
| `aggressive` | unicode escape **then** double URL-encode |

The primitive menu (`EVASION_TECHNIQUES`, `evasion.py:123`): `double_url`, `unicode`,
`html_entity`, `null_byte`, `case_variation`, `whitespace`. `apply_evasion()` is called
inside `_build_request()`; a scanner just passes `evasion_level` through.

> The replayer's own docstring at `replayer.py:34` mentions `point.inject()` — no such
> method exists. Ignore it; the real mechanism is `_build_request()` + the module-level
> `_inject_*` helpers.

---

## 9. Payloads

**`payloads.py` is the single source of truth** for a scanner's payloads.

- Payloads are declared as dataclasses (`value`, `technique`, plus scanner-specific
  fields such as `dbms`, `context`, `os`).
- Stages receive payload lists **by constructor injection**. A stage MUST NOT define its
  own inline payload list.
- Public accessors (`get_error_payloads()`, `get_payloads_for_context(ctx)`, …) are the
  interface. An accessor that nothing calls is a defect: either wire it or delete it.
- **OOB / canary payloads are the exception**: they are synthesized per run from a fresh
  unique token so callbacks cannot collide. The template still lives in `payloads.py`;
  only the token substitution happens at runtime.

Related helpers:

- `shared/scan/params.py` — injection-point extraction (not a payload source).

---

## 10. Findings output

- Stages `yield` findings; the plugin's `on_flow` yields them up to the loader, which
  publishes to the `finding` channel. `FindingStorage` persists them and attaches the
  triage pipeline (`on_saved`).
- A finding MUST carry the exact triggering request in `request_data`
  (`build_payload_request()` + serialize) so it is reproducible.
- Do not publish findings directly from a stage; return them in `StageResult`.

---

## 11. Registration and parity

Two load paths exist and **must expose the same scanner set**:

| Path | How scanners load | Where |
|---|---|---|
| Live proxy / autoscan | `discover_scanners()` scans `plugins/scanners/*/plugin.py` | `pwnproxy/plugins/core/loader.py:224`, called from `start()` (`:263`) |
| Standalone CLI / REST `/scan` | `_build_scan_loader()` constructs a fresh loader per call | `apps/terminal/cli/scan.py:79` |

**Normative rules**

- Adding a scanner MUST NOT require editing a hardcoded registry. Discovery is the
  registry; both paths MUST agree.
- The standalone path MUST forward the resolved scan config (depth, evasion, and the
  rest) into `load_builtin(plugin, config=...)`.

---

## 12. Conformance status

These are **known deviations** from the contract above. Each is a fix task tracked by
`fix/scanner-depth-integrity`. Do not build on the deviating behavior.

| # | Contract broken | Evidence | Status |
|---|---|---|---|
| C1 | Loader must inject config at load time | `load_builtin` hardcodes `config={}` — `loader.py:383` | ✅ fixed — `load_builtin(plugin, config=None)` |
| C2 | `on_flow` must carry no depth/evasion | `run_scan(flow, depth, evasion)` accepts and discards them — `loader.py:450` | ✅ fixed — `run_scan(flow)` only |
| C3 | `run_scan` signature = flow only | legacy `elif hasattr(plugin,"scan")` branch (3-arg) is dead — `loader.py:467` | ✅ fixed — branch removed |
| C4 | depth is a ceiling | `BudgetChain._depth_allows` treats depth as a floor → `deep` skips error-based — `chain.py:267` | ✅ fixed — `chain_from_depth` starts at FAST, `max_depth=<requested>` |
| C5 | `budget_ms` is whole-chain | `WAVE_BUDGET_MS` name implies per-wave — `chain.py:201` | ✅ fixed — renamed to `BUDGET_MS` (alias kept) |
| C6 | Every looping stage honors the deadline | only `BooleanBlindStage` overrides `set_deadline` — `sqli_stages.py:246` | ✅ fixed — base stores deadline, all stages check `_deadline_exceeded()` |
| C7 | Standalone == discovery set | `_build_scan_loader` hardcodes 5 scanners; `command_injection` is discovered live but never loaded standalone — `scan.py:88` | ✅ fixed — both use discovery, `command-injection` included |
| C8 | `payloads.py` is the single source | unused getters: XXE `get_error/oob/xinclude_payloads` (`xxe/payloads.py:81-98`), LFI `get_payloads` (`lfi/payloads.py:40`), SQLi `get_time_payloads` (`sqli/payloads.py:90`), SSRF `PayloadGenerator` (`ssrf/payloads.py:12`); stages inline lists instead | ✅ fixed — getters wired/removed, `STORED_PAYLOADS` moved, SSRF generator removed |
| C9 | Stages must not own payload lists | `xxe_stages`/`ssrf_stages`/xss `StoredStage` inline payloads — `xxe_stages.py:50`, `ssrf_stages.py`, `xss_stages.py:25` | ✅ fixed — templates moved to `payloads.py` |
| C10 | Injection helpers must work | `shared/scan/utils.py` query branch is a silent no-op (`:56`) and form branch raises `NameError` (`:83`); `XxeReplayer` fallback calls the nonexistent `point.inject()` — `xxe.py:58` | ✅ fixed — query/form branches corrected, `XxeReplayer` uses `super()._build_request()` |
| C11 | Test path == production path | golden tests construct `PluginContext(config=...)` directly and use `depth="standard"` — `tests/golden/test_scanner_targets.py:37,86,98,110` | ✅ fixed — converged to `load_builtin(plugin, config=...)` |
| C12 | Dead contracts removed | warn-only placeholders `load_from_package`, `list_available`, `run_hooks_request/response` — `loader.py:387,432,475` | ✅ fixed — removed |
| C13 | No phantom subsystems | second-order `PayloadStore` is never written by any scanner; REST endpoints only report empty stats — `shared/scan/payload_store.py`, `transport/rest/scanners.py:130` | ✅ fixed — store and endpoints removed |

All C-items resolved on `fix/scanner-depth-integrity`; §12 remains as the audit record.

---

## 13. How to build a new scanner

1. **Create the package**: `pwnproxy/plugins/scanners/<name>/` with `payloads.py`,
   optional `signatures.py`, `scanner.py`, `plugin.py`.
2. **Define payloads** in `payloads.py` as dataclasses plus public accessors. No payload
   data anywhere else.
3. **Write stages** in `shared/scan/stages/<name>_stages.py` (or the plugin package if
   truly specific). Stages receive data via constructor, return `StageResult`, and
   implement `set_deadline()` if they loop over the network.
4. **Build the scanner** in `scanner.py`: construct the chain **once** in `__init__`
   from injected data, expose `_scan_point(point) -> AsyncGenerator[Finding, None]`.
   Use `DetectionChain` for simple scanners, `chain_from_depth` for escalating ones.
5. **Define the plugin** in `plugin.py`: `ScannerPlugin` subclass with complete
   `PluginMetadata` (`name`, `version`, `category="scanner"`, `description`,
   `consumes=["flow"]`, `produces=["finding"]`, `capabilities`, `parameters`,
   `examples`). Read all config in `on_load()`:

   ```python
   async def on_load(self) -> None:
       depth = self.context.config.get("depth", "fast")
       evasion = self.context.config.get("evasion_level", "none")
       self._replayer = RequestReplayer()
       self._scanner = MyScanner(self._replayer, depth=depth, evasion=evasion)

   async def on_flow(self, flow):
       for point in _dedup(extract_params(flow)):
           async for finding in self._scanner._scan_point(point):
               yield finding

   async def on_unload(self) -> None:
       await self._replayer.close()
   ```

   `on_flow` takes **no** depth/evasion arguments.
6. **Make it discoverable**: placing the package under `plugins/scanners/` is enough for
   `discover_scanners()`. Do **not** add it to a hardcoded list (see C7).
7. **Write tests** ([§14](#14-testing-requirements-the-gate)).
8. **Run** `poetry run pytest -q tests/`.

Non-negotiables: fixed chain built once in `on_load`; config only via
`PluginContext.config`; data injected into stages; replayer created in `on_load` and
closed in `on_unload`; `payloads.py` is the only payload source.

---

## 14. Testing requirements (the gate)

Three tiers:

1. **Unit** — stages/chains may be constructed directly (`BudgetChain`, `DetectionChain`)
   with fakes. Fast, deterministic.
2. **Integration (real path)** — MUST go through the loader:

   ```python
   loader = await _build_scan_loader(scanners, config={"depth": "standard"})
   findings = await loader.run_scan(flow)          # flow only — no depth arg
   ```

   or, per plugin:

   ```python
   plugin = MyScannerPlugin()
   await loader.load_builtin(plugin, config={"depth": "standard"})
   findings = [f async for f in plugin.on_flow(flow)]
   ```

   **Forbidden:** constructing `PluginContext(config=...)` directly and calling
   `on_load()` in an integration test. That validates a construction production never
   uses (this is exactly defect C11).
3. **Golden fixtures** — every scanner MUST have at least one finding-producing test
   against its fixture target, driven through the real loader, plus a config-propagation
   assertion (the built chain reflects the requested depth/evasion).

A test that passes is only evidence if it exercises the production path. If a test's name
promises behavior the assertion does not check, fix the test.

---

## 15. Anti-patterns (forbidden)

- Reading `os.environ` / `config.toml` / globals inside a plugin.
- Passing depth or evasion as arguments to `on_flow` / `run_scan`.
- Rebuilding the detection chain per flow.
- Defining payload lists inline in stages instead of `payloads.py`.
- Defining an accessor/helper nobody calls (delete it or wire it).
- Constructing `PluginContext(config=...)` in an integration test.
- Adding a scanner to a hardcoded registry instead of relying on discovery.
- Creating an API endpoint without the engine behind it (see C13).
- Leaving warn-only placeholder methods as "compatibility".

---

## 16. File map

```
pwnproxy/plugins/core/          plugin framework
  base.py                       PwnPlugin, ScannerPlugin, PluginMetadata, PluginContext, Finding
  contracts.py                  consumer mixins (Flow/Finding/Surface/Evidence)
  loader.py                     UniversalPluginLoader, PluginLoader (load_builtin, run_scan, discover_scanners)
  chain.py                      DetectionDepth, DetectionStage, DetectionChain, BudgetChain, chain_from_depth
  config.py                     legacy [plugin] config reader (not wired to scanners)
  discovery.py / watchdog.py    PyPI discovery / hot-reload

pwnproxy/plugins/scanners/<name>/
  plugin.py                     ScannerPlugin subclass (reads config in on_load)
  scanner.py                    chain builder + _scan_point
  payloads.py                   payload dataclasses + accessors (single source)
  signatures.py                 error signatures (error-based scanners)

pwnproxy/shared/scan/
  params.py                     InjectionPoint + extract()
  replayer.py                   RequestReplayer (I/O, rate limiting, injection)
  replayers/xxe.py              XxeReplayer (XML body mutation)
  evasion.py                    EvasionLevel + transforms
  stages/<name>_stages.py       DetectionStage implementations

pwnproxy/shared/                canary.py, http_server.py, dns_server.py, hooks.py, findings/
```

References: `pwnproxy/plugins/core/base.py`, `pwnproxy/plugins/core/loader.py`,
`pwnproxy/plugins/core/chain.py`, `docs/ownership-matrix.md`, `docs/scanners.md`,
`docs/message-bus.md`.
