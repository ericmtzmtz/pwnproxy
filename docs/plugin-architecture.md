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
| `callback_port` | int | — | `DEFAULT_CALLBACK_PORT` (`17173`) | SSRF / OOB |

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

**Remote configuration.** The load-time path above is unchanged: only the loader populates
`PluginContext.config`. On top of it, a plugin that wants its configuration editable from outside
publishes a schema (`config_schema()`) and implements the methods that read and write its own store
(`config_read`, `config_write`, `collection_*`, `run_action`). The core stores nothing: it validates
every write against the published schema, calls the plugin's method and renders what comes back, so
one generic set of API routes, MCP tools and CLI commands serves every plugin — no client knows a
plugin by name. The author-facing rules are in [§3.4](#34-plugin-configuration-and-actions-for-authors).

Activation is a separate, machine-wide flag (`[plugin.activation]` in `config.toml`,
`POST /api/v1/plugins/{name}/toggle`): configuring a plugin does not enable it, and enabling it does
not reload its values.

A declared `secret` field is **write-only**: no read ever returns its value, only
`{"set": true|false}`, and the audit event carries key names, never values. Writing one requires a
token of scope `full` (`pwnproxy/transport/rest/auth.py`); the MCP runs with the `agent` scope, so a
secret can be neither read nor written through the MCP tools.
That is not a sandbox. The `agent` scope keeps secrets out of the MCP tools, but it does not
contain an agent with a shell on the machine: such an agent can read `~/.pwnproxy/api-token` and get
`full`.

### 3.3 `Finding`

Defined in `pwnproxy/shared/scan/finding.py` (re-exported by
`pwnproxy/plugins/core/base.py`, so `from pwnproxy.plugins.core.base import Finding`
keeps working). Every scanner MUST emit fully populated `Finding` objects:

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

### 3.4 Plugin configuration and actions (for authors)

The load-time contract of §3.2 does not change. A plugin that wants its settings editable from
outside **publishes a schema** and implements the methods that read and write its own store. The core
stores no configuration: it validates a request against the published schema, calls the plugin's
method and renders what comes back. One generic set of API routes, MCP tools and CLI commands serves
every plugin, so nothing in the Web UI, the MCP or the CLI knows a plugin by name.

Everything lives in `pwnproxy/plugins/core/config_schema.py` (the vocabulary) and
`pwnproxy/plugins/core/config_service.py` (the contract, with the error table in its docstring).

#### 3.4.1 The schema

`config_schema()` returns a `PluginConfigSchema` built from `FieldSpec`, `CollectionSpec` and
`ActionSpec`. It is validated on every call: a broken one is a `409` and **no** field of it is
published.

```python
from pwnproxy.plugins.core.config_schema import (
    ActionSpec,
    CollectionSpec,
    FieldSpec,
    PluginConfigSchema,
)

# Settings: one flat object. Values the plugin reads when it loads or when it runs.
ENVIRONMENT = FieldSpec(
    "environment",
    "enum",
    choices=("lab", "staging"),    # enum => choices is mandatory
    default="lab",                 # reported when the plugin has no value
    help="Where the checks run.",
)
RETRIES = FieldSpec("retries", "integer", minimum=0, maximum=5)

# A collection: a list of items, each shaped by `item`, at most `max_items` of them.
WEBHOOKS = CollectionSpec(
    name="webhooks",               # route segment: /plugins/<name>/collections/webhooks
    help="Webhooks the checks call.",
    max_items=5,                   # capacity: the server answers 409 when it is full
    item=(
        FieldSpec("name", "string", required=True, max_length=64,
                  help="Unique; how the client addresses the item."),
        FieldSpec("url", "string", required=True, max_length=2048,
                  help="Where the test request goes. The plugin validates it."),
        FieldSpec("events", "array", items="string", max_items=32,
                  help="Events this webhook subscribes to."),
        FieldSpec("status", "enum", choices=("active", "failing"), read_only=True,
                  help="The plugin recomputes it; a client that sends it gets 422."),
        # The secrets of a webhook: string only, no default, never returned.
        FieldSpec("signing_key", "string", secret=True, max_length=4096,
                  help="Used to sign the request. Never returned."),
        FieldSpec("auth_header", "string", secret=True, max_length=4096,
                  help="Sent as the Authorization header. Never returned."),
    ),
)

# An action: an operation run on demand, with parameters the client sends.
SEND_TEST = ActionSpec(
    name="send_test",              # route segment: /plugins/<name>/actions/send_test
    long_running=True,             # 202 + task_id; the result lands in GET /tasks/{id}
    requires_scope="full",         # the token scope it needs; undeclared means "full"
    help="Sends one test request to a webhook and reports the answer.",
    parameters=(
        FieldSpec("name", "string", required=True),
        FieldSpec("payload", "string", required=True, max_length=8192),
    ),
)

def config_schema(self) -> PluginConfigSchema:
    return PluginConfigSchema(
        settings=(ENVIRONMENT, RETRIES),
        collections=(WEBHOOKS,),
        actions=(SEND_TEST,),
    )
```

`FieldSpec` attributes: `key`, `type` (`string` \| `integer` \| `number` \| `boolean` \| `enum` \|
`array`), `help`, `required`, `secret`, `read_only`, `default`, `choices`, `minimum`, `maximum`,
`max_length`, `max_items`, `items`. `required` only bites on a **create**: a `PATCH` validates the
keys it carries and leaves every other key alone. Array items are strings today.

The published form (`GET /api/v1/plugins/{name}/schema`) is `FieldSpec.to_dict()`: `key`, `type`,
`required`, `secret` and `read_only` are **always** present — a client should not have to tell
"absent" from `false` — while `help` and the type-specific attributes (`default`, `choices`,
`minimum`, `maximum`, `max_length`, `max_items`, `items`) appear only when declared. The payload is
`{"plugin", "schema_version", "settings", "collections", "actions"}` and nothing else;
`schema_version` is `1`, and growing the shape (a new field type, a new attribute) means a new
number, never a silent reinterpretation.

#### 3.4.2 The eight optional methods

A plugin may implement any of them, plain or `async` — the core awaits when needed, so the plugin
does not have to know how it is called. `PwnPlugin` declares none of them: a plugin that implements
no method simply has no configuration, and the routes answer `200` with empty lists.

| Method | Called by | Must return |
|---|---|---|
| `config_schema()` | every configuration route, before anything else | `PluginConfigSchema` |
| `config_read()` | `GET /api/v1/plugins/{name}/settings` | flat `{key: value}`; a secret adds `"<key>__set": true` |
| `config_write(values)` | `PATCH /api/v1/plugins/{name}/settings` | nothing (the response is read back with `config_read`) |
| `collection_list(collection)` | `GET /api/v1/plugins/{name}/collections/{collection}` | `[{"id": …, <field>: …}, …]` |
| `collection_create(collection, values)` | `POST /api/v1/plugins/{name}/collections/{collection}` | the created item, with its `id` |
| `collection_update(collection, item_id, values)` | `PATCH …/collections/{collection}/{item_id}` | the updated item |
| `collection_delete(collection, item_id)` | `DELETE …/collections/{collection}/{item_id}` | nothing (`204`) |
| `run_action(action, parameters)` | `POST /api/v1/plugins/{name}/actions/{action}` | the action's result, or `{"status": "running", "task_id": …}` |

- A write returns the object again, rendered: settings come back as
  `{"plugin", "schema_version", "values"}`, an item as `{"id", "values"}` and a collection as
  `{"plugin", "collection", "schema_version", "max_items", "items"}`.
- `run_action` returns `{"status": "completed", "result": <yours>}` for a short action (`200`) and
  `{"status": "running", "task_id": …}` for a `long_running` one (`202`); the result then lands in
  `GET /api/v1/tasks/{task_id}`. A long action needs a task store in the process (`503` otherwise).
- A missing method is `409` `plugin '<n>' declares no <method>`; a collection or action the schema
  does not declare is `404`.

#### 3.4.3 Rules the core enforces for you

- **`secret` is only allowed on `string`**, so `{"set": bool}` can never be confused with a value,
  and a secret field **cannot declare a `default`** — the schema is published, so a default would
  leak it.
- **A secret is write-only.** `render_values()` is the only place that builds the read form: for a
  secret field it emits `{"set": …}` from `"<key>__set"` and **discards whatever the plugin returned
  for that key**, so a plugin that forgets its half of the contract leaks nothing. Only key *names*
  reach the audit event and the log line.
- **An action parameter can be neither `secret` nor `read_only`** (the schema is rejected with
  `409`). A long action persists its parameters in the task store, so a secret there would be a
  secret at rest outside the plugin's own store: an action uses a secret the plugin already holds.
- **An action result never carries a secret.** The task store persists results and the MCP reads
  them: return the finding, the status code or the diff, never the credential that produced it.
- **The core validates the shape; the plugin decides the business rule.** The core checks a
  declared key (`unknown field`), the JSON type, `choices`, `minimum`/`maximum`, `max_length`,
  `max_items`, `required` on create, `read_only` refused, `null` refused, and the collection's
  capacity (`409` `collection '<c>' is full (max <n> items)`). Everything else is yours: uniqueness,
  "webhook names must be unique", whether the URL answers, what "failing" means. Raise
  `PluginValidationError(field, message)` — the client receives **your** `422`
  `{"field", "message"}`, untouched — and do not widen a `SchemaViolation` nor invent an HTTP status.
  A `422` from a collection item qualifies the field with the collection (`webhooks.signing_key`).
- **`config_write` and `collection_*` are the only seam, and there is no reload.** Persist the change
  *and* apply it to the live state of the plugin there. The core does not reload the plugin after a
  write: that would replay the events the bus buffered while it was off and restart its consumer
  tasks.
- **`__init__` must have no side effects** (no network, no store opened). A plugin that is **not
  loaded** is still configurable: the core builds a *disposable* instance from the catalog's factory
  and never calls `on_load()` on it. Actions are the exception — they need a live plugin (`409`
  `plugin '<n>' is not loaded`).
- **Activation is not configuration.** The `toggle` flips the machine-wide `[plugin.activation]`
  flag; it does not touch your values and your `config_write` does not enable anything.

#### 3.4.4 The `agent` scope, from the plugin's side

An `agent` token cannot write a declared secret (a `403` whose message names the rule and points at
the Web UI or the CLI) and cannot run an action declared `requires_scope="full"` (a `403` with the
generic scope body). It **can** write every non-secret setting: that is the split, and it is the
reason a setting that must not be changed by an agent is a secret or moves behind an action. The
bound of the scope is in §3.2 and has not changed: an agent with a shell on the same machine reads
`~/.pwnproxy/api-token` and gets `full`.

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

`pwnproxy/plugins/core/chain.py`. The base types (`DetectionDepth`, `StageResult`,
`DetectionStage`) live in `pwnproxy/shared/scan/stage.py` and are re-exported from
`chain.py`; the chain implementations stay in `chain.py`.

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

`DetectionStage` (`pwnproxy/shared/scan/stage.py`, re-exported by
`pwnproxy/plugins/core/chain.py`). Contract:

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
- A plugin that does **not** run inside the proxy process (an external producer, a
  premium module, a script) publishes through `POST /api/v1/findings` instead of
  writing the database itself: the endpoint validates the body, checks the `scanner`
  against this catalog, persists with the same `FindingStorage.save` (triage included)
  and only then publishes the `finding` event with the active `session_id`. See
  `docs/api.md`.

---

## 11. Registration and parity

Discovery lives in **one** place: `pwnproxy/plugins/core/catalog.py`
(`discover_plugins()`). Every load path consumes it and exposes the same set:

| Path | How scanners load | Where |
|---|---|---|
| Live proxy / autoscan | `UniversalPluginLoader.start()` → `refresh_catalog()` loads the enabled catalog records | `pwnproxy/plugins/core/loader.py` |
| Standalone CLI / REST `/scan` | `build_scan_loader()` builds a fresh loader from the catalog | `pwnproxy/plugins/core/catalog.py` |
| TUI / `GET /api/v1/plugins` | read the catalog itself | `apps/terminal/tui/scanner_widget.py`, `transport/rest/plugins.py` |

The catalog has two sources:

1. **Drop-in** — a package under `pwnproxy/plugins/scanners/<name>/plugin.py` (the six
   built-ins: `command-injection`, `lfi`, `sqli`, `ssrf`, `xss`, `xxe`). `source` is
   `"builtin"` and `package` is `pwnproxy`.
2. **Installed package** — any distribution that declares an entry point in the
   `pwnproxy.plugins` group:

   ```toml
   [project.entry-points."pwnproxy.plugins"]
   authorization-matrix = "pwnproxy_pro.matrix:AuthorizationMatrixPlugin"
   ```

   The value resolves to a `PwnPlugin` subclass (instantiated without arguments) or to
   an already built instance; anything else is a catalog entry with `error`, never a
   crash. `source` is `"installed"` and `package`/`version` come from the distribution
   metadata. A package **without** an entry point is invisible: the name is not a
   contract, the entry point is. `discover_installed()` (the `pwnproxy plugin list`
   view of `[tool.pwnproxy]` packages) is not a discovery path.

   Resolving an entry point imports the package, so module-level code runs even while
   the plugin is disabled. A class entry point is only instantiated when the loader
   actually loads it (unless its `metadata` is not a class attribute).

**Activation** is machine-wide and lives in `~/.pwnproxy/config.toml`:

```toml
[plugin.activation]
sqli = false
authorization-matrix = true
```

Absent name ⇒ built-in enabled, installed **disabled**. It is not part of
`modules.json` and does not change when the user switches session: there is one loader
per process. Enabling/disabling is `POST /api/v1/plugins/{name}/toggle`, which persists
first and only then applies the change in memory.

**Normative rules**

- Adding a scanner MUST NOT require editing a hardcoded registry; there is none left
  (`tests/architecture/test_scanner_registries.py` fails if one comes back).
- Both load paths MUST agree, and both MUST forward the resolved scan config (depth,
  evasion, callback port) into `load_builtin(plugin, config=...)`.
- A broken plugin (import, instantiation or `on_load` failure) MUST be recorded in the
  catalog with its reason and skipped; the proxy keeps starting and the other plugins
  keep scanning.
- A name collision is resolved in favour of the built-in; the installed one stays in the
  catalog with `error` and never loads.

---

## 12. Conformance status

These are **known deviations** from the contract above. The first block was tracked by
`fix/scanner-depth-integrity`; C14 and C15 by `installed-plugin-discovery`. Do not build
on the deviating behavior.

| # | Contract broken | Evidence | Status |
|---|---|---|---|
| C1 | Loader must inject config at load time | `load_builtin` hardcodes `config={}` — `loader.py:383` | ✅ fixed — `load_builtin(plugin, config=None)` |
| C2 | `on_flow` must carry no depth/evasion | `run_scan(flow, depth, evasion)` accepts and discards them — `loader.py:450` | ✅ fixed — `run_scan(flow)` only |
| C3 | `run_scan` signature = flow only | legacy `elif hasattr(plugin,"scan")` branch (3-arg) is dead — `loader.py:467` | ✅ fixed — branch removed |
| C4 | depth is a ceiling | `BudgetChain._depth_allows` treats depth as a floor → `deep` skips error-based — `chain.py:267` | ✅ fixed — `chain_from_depth` starts at FAST, `max_depth=<requested>` |
| C5 | `budget_ms` is whole-chain | `WAVE_BUDGET_MS` name implies per-wave — `chain.py:201` | ✅ fixed — renamed to `BUDGET_MS` (alias kept) |
| C6 | Every looping stage honors the deadline | only `BooleanBlindStage` overrides `set_deadline` — `sqli_stages.py:246` | ✅ fixed — base stores deadline, all stages check `_deadline_exceeded()` |
| C7 | Standalone == discovery set | `_build_scan_loader` hardcoded 5 scanners; `command_injection` was discovered live but never loaded standalone — `scan.py:88` | ✅ fixed twice: first by sharing discovery, then by removing both registries — `discover_plugins()` is now the only source (`pwnproxy/plugins/core/catalog.py`), and the loader, the CLI, the REST `/scan`, `/scanners/trigger`, the TUI and `GET /plugins` all read it (see §11) |
| C8 | `payloads.py` is the single source | unused getters: XXE `get_error/oob/xinclude_payloads` (`xxe/payloads.py:81-98`), LFI `get_payloads` (`lfi/payloads.py:40`), SQLi `get_time_payloads` (`sqli/payloads.py:90`), SSRF `PayloadGenerator` (`ssrf/payloads.py:12`); stages inline lists instead | ✅ fixed — getters wired/removed, `STORED_PAYLOADS` moved, SSRF generator removed |
| C9 | Stages must not own payload lists | `xxe_stages`/`ssrf_stages`/xss `StoredStage` inline payloads — `xxe_stages.py:50`, `ssrf_stages.py`, `xss_stages.py:25` | ✅ fixed — templates moved to `payloads.py` |
| C10 | Injection helpers must work | `shared/scan/utils.py` query branch is a silent no-op (`:56`) and form branch raises `NameError` (`:83`); `XxeReplayer` fallback calls the nonexistent `point.inject()` — `xxe.py:58` | ✅ fixed — query/form branches corrected, `XxeReplayer` uses `super()._build_request()` |
| C11 | Test path == production path | golden tests construct `PluginContext(config=...)` directly and use `depth="standard"` — `tests/golden/test_scanner_targets.py:37,86,98,110` | ✅ fixed — converged to `load_builtin(plugin, config=...)` |
| C12 | Dead contracts removed | warn-only placeholders `load_from_package`, `list_available`, `run_hooks_request/response` — `loader.py:387,432,475` | ✅ fixed — removed |
| C13 | No phantom subsystems | second-order `PayloadStore` is never written by any scanner; REST endpoints only report empty stats — `shared/scan/payload_store.py`, `transport/rest/scanners.py:130` | ✅ fixed — store and endpoints removed |
| C14 | One registry, not four | the catalog did not exist and the list of scanner names was copied in `cli/scan.py` (dict of 6), `cli/findings.py` (`VALID_SCANNERS`), `tui/scanner_widget.py` (`SCANNER_NAMES`) and `transport/rest/scanners.py` (`VALID_SCANNERS`), while the loader walked the tree by itself | ✅ fixed — `pwnproxy/plugins/core/catalog.py` is the only source, consumed by the loader, the CLI, the REST endpoints, the TUI and `GET /plugins`; `tests/architecture/test_scanner_registries.py` and `TestSingleDiscoverySource` guard it |
| C15 | Activation is machine-wide, not session state | `SessionManager._gather_module_state()` wrote a `plugins` map into `modules.json` and `_apply_module_state()` activated/deactivated plugins on every session switch, although one loader serves the whole process | ✅ fixed — `[plugin.activation]` in `~/.pwnproxy/config.toml`, written by the toggle before it answers; a legacy `plugins` key is ignored with a single warning |

All C-items are resolved; §12 remains as the audit record.

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
6. **Make it discoverable**: either drop the package under `plugins/scanners/`, or ship
   it as its own distribution with an entry point in the `pwnproxy.plugins` group
   (§11). Do **not** add it to a hardcoded list (see C7/C14).
7. **Write tests** ([§14](#14-testing-requirements-the-gate)).
8. **Run** `poetry run pytest -q tests/`.

Non-negotiables: fixed chain built once in `on_load`; config only via
`PluginContext.config`; data injected into stages; replayer created in `on_load` and
closed in `on_unload`; `payloads.py` is the only payload source.

A scanner whose settings must be editable from outside — or that offers an on-demand action such
as "send one test request" — publishes a schema on top of this
([§3.4](#34-plugin-configuration-and-actions-for-authors)): the fields and actions are declared in
`config_schema()`, and every change arrives through `config_write` / `collection_*`, which must
persist it **and** apply it to the live plugin because the core does not reload it. The store is
yours; `PluginContext.config` keeps the load-time reads.

**Trust boundary.** A plugin runs inside the proxy process, with the user's permissions
and no sandbox: it can read the database, the traffic and the file system. Resolving its
entry point already imports the package. Enabling a plugin — including one installed
from a package — is a decision to trust that code, which is why installed plugins start
disabled and the state is machine-wide.

---

## 14. Testing requirements (the gate)

Three tiers:

1. **Unit** — stages/chains may be constructed directly (`BudgetChain`, `DetectionChain`)
   with fakes. Fast, deterministic.
2. **Integration (real path)** — MUST go through the loader:

   ```python
   from pwnproxy.plugins.core.catalog import build_scan_loader

   loader = await build_scan_loader(scanners, config={"depth": "standard"})
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

#### A plugin that declares a schema

Optional. A plugin that implements none of the eight methods of
[§3.4](#34-plugin-configuration-and-actions-for-authors) has no configuration to test. One that
publishes `config_schema()` MUST add the cases below, driven through `PluginConfigService` — the
path the REST routes, the MCP tools and the CLI take — and not by reaching into its own store:

- **The declared schema validates.** `validate_schema(plugin.config_schema())` does not raise and
  the call returns a `PluginConfigSchema`. A schema the core rejects is a `409` that publishes
  nothing, so a test that only checks "the route answers" hides it.
- **No read returns a secret.** After writing a `secret` field (`signing_key`), neither
  `read_settings()` nor `list_items()` carries the value: `render_values()` publishes a secret as
  `{"set": true}`, so the probe string you wrote appears nowhere in the response.
- **No action result returns a secret.** `run_action("send_test", …)` may report the URL, the
  status code or the diff; assert the result holds no secret value. The task store persists it and
  the MCP reads it, so a secret there is a secret at rest outside your store.
- **Business rules raise `PluginValidationError`.** A duplicate webhook `name`, an unreachable URL:
  the client receives **your** `422` `{"field", "message"}`, with the field qualified by the
  collection (`webhooks.name`) — not a `500`, and not a widened `SchemaViolation`.
- **`__init__` has no side effects.** Build the instance the way the core does for a plugin that is
  not loaded — the catalog's factory, no `on_load()` — then write a setting and list a collection:
  no connection may be opened and no task started. A `__init__` that reaches the network fails
  here, and it would also break `GET …/schema` with the plugin disabled.
- **The collection respects `max_items`.** Fill it to the declared capacity and assert the next
  create is a `409` `collection 'webhooks' is full (max 5 items)`: the core enforces the count, the
  test proves the number you declared is the one you meant.

---

## 15. Anti-patterns (forbidden)

- Reading `os.environ` / `config.toml` / globals inside a plugin.
- Passing depth or evasion as arguments to `on_flow` / `run_scan`.
- Rebuilding the detection chain per flow.
- Defining payload lists inline in stages instead of `payloads.py`.
- Defining an accessor/helper nobody calls (delete it or wire it).
- Constructing `PluginContext(config=...)` in an integration test.
- Adding a scanner to a hardcoded registry instead of relying on discovery (C14).
- Reading `config.toml` activation from anywhere but `plugins/core/config.py`.
- Creating an API endpoint without the engine behind it (see C13).
- Leaving warn-only placeholder methods as "compatibility".

---

## 16. File map

```
pwnproxy/plugins/core/          plugin framework
  base.py                       PwnPlugin, ScannerPlugin, PluginMetadata, PluginContext (+ re-export Finding)
  catalog.py                    discover_plugins (built-ins + entry points), PluginRecord, build_scan_loader, scan_config
  config.py                     config.toml: [plugin] legacy block + [plugin.activation] (plugin_enabled, set_plugin_enabled, atomic write)
  config_schema.py              configuration vocabulary: FieldSpec, CollectionSpec, ActionSpec, PluginConfigSchema, validate_schema, render_values, PluginValidationError
  config_service.py             PluginConfigService (schema, settings, collections, actions) + the error → HTTP status table in its docstring
  contracts.py                  consumer mixins (Flow/Finding/Surface/Evidence)
  loader.py                     UniversalPluginLoader, PluginLoader (refresh_catalog, toggle, run_scan)
  chain.py                      DetectionChain, BudgetChain, chain_from_depth (+ re-exports from shared/scan/stage.py)
  discovery.py / watchdog.py    PyPI discovery / hot-reload

pwnproxy/transport/rest/
  plugin_config.py              generic /api/v1/plugins/{name}/{schema,settings,collections,actions} routes (scope checks; knows no plugin by name)

pwnproxy/plugins/scanners/<name>/
  plugin.py                     ScannerPlugin subclass (reads config in on_load)
  scanner.py                    chain builder + _scan_point
  payloads.py                   payload dataclasses + accessors (single source)
  signatures.py                 error signatures (error-based scanners)

pwnproxy/shared/scan/
  finding.py                    Finding (canonical home; re-exported by plugins/core/base.py)
  stage.py                      DetectionDepth, StageResult, DetectionStage
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
