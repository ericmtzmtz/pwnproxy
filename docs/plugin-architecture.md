# Plugin Architecture

This document defines the requirements for all pwnproxy plugins (built-in and third-party).

## Self-Describing Plugin Pattern

**MANDATORY**: All plugins MUST expose complete metadata through the plugin interface. This enables:
- AI agents to auto-discover capabilities
- Dynamic UI generation
- Automated documentation
- Parameter validation

## Plugin Metadata

Every plugin MUST define these class attributes:

```python
class MyScannerPlugin(ScannerPlugin):
    # Required metadata
    name = "my-scanner"
    version = "1.0.0"
    author = "Your Name"
    category = "scanner"  # or "hook"
    description = "Detects XYZ vulnerabilities using ABC technique"
    
    # Parameter schema (MANDATORY for AI discovery)
    parameters = {
        "detection_depth": {
            "type": "string",
            "required": False,
            "default": "standard",
            "choices": ["fast", "standard", "deep"],
            "description": "Detection thoroughness level"
        },
        "timeout": {
            "type": "integer",
            "required": False,
            "default": 30,
            "description": "Request timeout in seconds"
        }
    }
    
    # Capabilities (what this plugin can detect)
    capabilities = [
        "sql-injection",
        "blind-sqli",
        "time-based-sqli"
    ]
    
    # Usage examples for AI agents
    examples = [
        {
            "description": "Scan for SQL injection with deep detection",
            "params": {"detection_depth": "deep", "timeout": 60}
        }
    ]
```

## API Response Format

`GET /api/v1/plugins` returns:

```json
{
  "plugins": [
    {
      "name": "sqli",
      "version": "1.0.0",
      "author": "pwnproxy",
      "category": "scanner",
      "enabled": true,
      "description": "SQL injection detector with error-based, blind, and time-based techniques",
      "parameters": {
        "detection_depth": {
          "type": "string",
          "required": false,
          "default": "standard",
          "choices": ["fast", "standard", "deep"],
          "description": "Detection thoroughness level"
        }
      },
      "capabilities": ["sql-injection", "blind-sqli", "time-based-sqli"],
      "examples": [
        {
          "description": "Deep SQL injection scan",
          "params": {"detection_depth": "deep"}
        }
      ]
    }
  ]
}
```

## Parameter Types

Supported parameter types:
- `string` — text value, optional `choices` array
- `integer` — whole number, optional `min`/`max`
- `float` — decimal number, optional `min`/`max`
- `boolean` — true/false
- `array` — list of values, specify `items` type

## Capabilities

Capabilities are lowercase, hyphenated strings describing what the plugin detects or does:
- `sql-injection`, `xss`, `ssrf`, `lfi`, `xxe`
- `blind-detection`, `out-of-band`, `second-order`
- `waf-evasion`, `context-aware`

Use existing capabilities when possible. New capabilities should be documented.

## Implementation Checklist

When creating a new plugin:
- [ ] Define all metadata attributes (name, version, author, category, description)
- [ ] Define `parameters` schema with types, defaults, descriptions
- [ ] Define `capabilities` array
- [ ] Provide at least one `examples` entry
- [ ] Test that `GET /plugins` returns complete metadata
- [ ] Verify AI agent can discover and use the plugin without reading source code

## Why This Matters

The self-describing pattern enables:
1. **AI Agent Autonomy** — Agents can discover new plugins and their parameters without manual updates to SKILL.md
2. **Dynamic UI** — Web UI can generate parameter forms automatically
3. **Documentation** — API docs stay in sync with actual plugin capabilities
4. **Validation** — Parameters are validated against schema before execution

## Scanner Pipeline

Every scanner follows this execution pipeline:

```
ScannerPlugin.on_load()
  └─ self._replayer = RequestReplayer()
  └─ self._chain = DetectionChain([                  ← chain construido UNA VEZ
       Stage(replayer, signatures, payloads, evasion),
       ...
     ], DetectionDepth(depth))

ScannerPlugin.on_flow(flow)
  └─ extract_params(flow) → list[InjectionPoint]
       └─ for each point: scanner._scan_point(point)
            └─ self._chain.run(flow, [point])         ← chain ya existe, no se reconstruye
                 └─ stages execute in order
                      └─ replayer.replay(point, payload) → check response
```

### Stage Constructor Injection

Stages in `shared/scan/stages/` do **not** import scanner-specific data (signatures, payload lists). Instead, data is injected via constructor at chain-build time:

```python
# shared/scan/stages/sqli_stages.py — recibe datos, no importa
class ErrorBasedStage(DetectionStage):
    def __init__(self, replayer, signatures: dict[str, list[Pattern]], error_payloads: list[Payload], evasion_level="none"):
        self._signatures = signatures
        self._error_payloads = error_payloads
        ...

# plugins/scanners/sqli/plugin.py — inyecta datos al construir el chain
from .signatures import ERROR_SIGNATURES
from .payloads import get_error_payloads, TIME_PAYLOADS

chain = DetectionChain([
    ErrorBasedStage(replayer, ERROR_SIGNATURES, get_error_payloads()),
    TimeBlindStage(replayer, TIME_PAYLOADS),
    BooleanBlindStage(replayer),     # payloads inline, no necesita inyección
    OOBStage(replayer),
], DetectionDepth(depth))
```

This eliminates the `shared/ → plugins/` dependency and allows third-party plugins to supply custom signatures/payloads without modifying shared code.

### _scan_point Contract

`_scan_point` receives only the injection point. Depth and evasion are baked into the chain at construction time:

```python
async def _scan_point(self, point: InjectionPoint) -> AsyncGenerator[Finding, None]:
    flow = Flow(id=point.flow_id, method=point.method, url=point.url, ...)
    async for finding in self._chain.run(flow, [point]):
        yield finding
```

### InjectionPoint

A single `InjectionPoint` type is used across the entire pipeline, defined in `shared/scan/params.py`:

```python
@dataclass
class InjectionPoint:
    name: str
    value: str
    location: str        # "query", "body", "cookie", "header"
    flow_id: str
    method: str
    url: str
    host: str
    path: str
    original_headers: dict[str, str]
    original_body: Optional[str]

    @property
    def key(self) -> tuple:
        return (self.method, self.host + self.path, self.name, self.location)
```

The `key` property is used by `DetectionChain` for deduplication across stages.

### Finding Contract

All scanners MUST emit `Finding` objects with the following fields:
- `scanner`: Name of the scanner plugin (e.g., `"sqli"`, `"xss"`).
- `url`: Target URL where the finding was detected.
- `method`: HTTP method (`GET`, `POST`, etc.).
- `param_name`: The parameter name that was tested.
- `param_location`: Where the parameter was found (`query`, `body`, `cookie`, `header`).
- `technique`: Detection technique (free-form string, see vocabulary convention).
- `severity`: One of `low`, `medium`, `high`, `critical`.
- `confidence`: One of `tentative`, `confirmed`.
- `payload`: The payload that triggered the finding.
- `evidence`: Human-readable string describing what was observed.
- `timestamp`: UTC datetime of detection.
- `extra`: Optional dict for scanner-specific metadata.

All fields SHALL be populated. Empty defaults (empty string, `None`) are not allowed for `scanner`, `url`, `technique`, `severity`, `confidence`, `evidence`.

#### Technique Vocabulary Convention

Each scanner plugin SHALL define a class-level `techniques: list[str]` attribute listing the technique values it may emit. The following values are RECOMMENDED:
- `"error-based"` — Detection via error messages in response
- `"boolean-blind"` — Detection via response size/content differences
- `"time-based"` — Detection via response time delays
- `"oob"` — Detection via out-of-band callbacks
- `"reflected"` — Reflected input in response
- `"stored"` — Stored/persistent injection
- `"dom-based"` — Client-side DOM manipulation
- `"path-traversal"` — File path traversal
- `"command-injection"` — OS command injection
- `"code-injection"` — Server-side code injection
- `"template-injection"` — SSTI

#### Severity Scale

Severity SHALL follow this convention:
- `low` — Informational, low-impact exposure
- `medium` — Limited impact, requires specific conditions
- `high` — Significant impact, exploitable
- `critical` — Remote code execution, full compromise

#### Confidence Scale

Confidence SHALL follow this convention:
- `tentative` — Suspicious behavior observed, may be a false positive
- `confirmed` — Verified by secondary technique or manual confirmation

#### Evidence Format

Evidence SHALL be a human-readable string. It SHOULD include specific values to allow the user to understand the detection without inspecting raw responses. Examples:
- `"Response length diff: TRUE=246, FALSE=158 (diff=88)"`
- `"Matched SQL error: syntax error near '1=1'"`
- `"Reflected payload in HTML body at line 42"`
- `"Response time 5.2s vs baseline 0.1s (52x delay)"`
- `"OOB callback received from 192.168.1.1:443"`

### DetectionChain

The chain framework (`plugins/core/chain.py`) orchestrates detection stages. Stages run in order; confirmed injection points are removed from subsequent stages.

Stages import `InjectionPoint` from `shared/scan/params.py`, NOT from `plugins/core/chain.py`.

### Adding a New Scanner

1. Create scanner data (`signatures.py` if error-based detection, `payloads.py` with payload lists) in `plugins/scanners/<name>/`
2. Create scanner in `plugins/scanners/<name>/scanner.py` that builds a `DetectionChain` in `__init__` with injected data, and exposes `_scan_point(self, point) -> AsyncGenerator[Finding, None]`
3. Create plugin in `plugins/scanners/<name>/plugin.py` extending `ScannerPlugin` that constructs the chain once in `on_load()`
4. Register in `apps/terminal/cli/start.py`
5. Add tests matching existing scanner test patterns

## References

- Plugin base classes: `pwnproxy/plugin/base.py`
- Plugin loader: `pwnproxy/plugin/loader.py`
- API endpoint: `GET /api/v1/plugins`
- OpenSpec proposals: `openspec/changes/scanner-premium-depth/`

---

## 10.1a: Plugin types and contracts

| Type | Description | Core contract |
|------|-------------|---------------|
| `ScannerPlugin` | Consumes **flows** (HTTP request/response pairs) and produces **findings**. | Implements `ScannerPlugin.on_flow(flow) → None` and registers a `DetectionChain`. |
| `HookPlugin` *(future)* | Provides lifecycle hooks such as `on_request` / `on_response` that can be attached to the proxy core. | Implements `HookPlugin.register(bus: HookBus) → None`. |
| `CrawlerPlugin` | Walks a target surface (spider) and feeds generated surfaces to the scanner pipeline. | Implements `CrawlerPlugin.on_surface(surface) → Surface \| None`. |
| `ExploiterPlugin` | Takes a confirmed finding and attempts an exploitation step, emitting **evidence**. | Implements `ExploiterPlugin.on_evidence(evidence) → Finding \| None`. |

### Shared contracts
- **`PluginMetadata`** – defines the static description of a plugin:
```python
@dataclass
class PluginMetadata:
    name: str
    version: str
    consumes: List[Literal["flow"]] = field(default_factory=lambda: ["flow"])
    produces: List[Literal["finding"]] = field(default_factory=lambda: ["finding"])
    description: str = ""
```
- **`Finding`** – the universal output contract used by every scanner:
```python
@dataclass
class Finding:
    scanner: str                         # plugin name, e.g. "sqli"
    url: str                             # target URL
    method: str                          # HTTP method
    param_name: str                      # injected parameter name
    param_location: str                  # "query" | "body" | "cookie" | "header"
    technique: str                       # e.g. "error-based", "time-based-blind"
    severity: str                        # "low" | "medium" | "high" | "critical"
    confidence: str                      # "tentative" | "confirmed"
    payload: str                         # payload that triggered the finding
    evidence: str                        # human-readable description
    timestamp: datetime                  # UTC detection time
    extra: dict = field(default_factory=dict)
```
> **References**: `pwnproxy/plugins/core/base.py` (abstract plugin base classes) and `pwnproxy/plugins/core/contracts.py` (metadata & finding definitions).

---

## 10.1b: Plugin lifecycle

1. **Load** – `UniversalPluginLoader.load()` (or `PluginLoader.load_builtin()`) registers the plugin and calls `plugin.on_load()`. The plugin constructs its `DetectionChain` and any shared resources (e.g., `RequestReplayer`) during this phase.
2. **Start** – `UniversalPluginLoader.start()` spawns long‑running consumer tasks (e.g., an `asyncio.Queue` consumer on the *flow* channel) that drive the plugin logic.
3. **Scan / Process** – For a `ScannerPlugin`, each incoming flow triggers `ScannerPlugin.on_flow(flow)`. The plugin extracts `InjectionPoint`s and delegates to the pre‑built `DetectionChain`.
4. **Unload / Stop** – `UniversalPluginLoader.unload()` cancels consumer tasks, calls `plugin.on_unload()` (which closes resources like the `RequestReplayer`), and removes the plugin from the registry.

The loader guarantees that **only one instance** of a plugin exists at a time and that all background tasks are cleaned up when the proxy shuts down.

---

## 10.1j: MessageBus integration

### Communication channels

All plugins communicate through the `MessageBus` (see `docs/message-bus.md`). Scanner plugins consume flows and produce findings via bus topics:

| Plugin type | Consumes | Produces |
|------------|----------|----------|
| `ScannerPlugin` | `proxy.flow` (via `flow` legacy topic) | `finding.new` |
| `CrawlerPlugin` | `scan.request` | `surface.*` |
| `ExploiterPlugin` | `finding.confirmed` | `evidence.*` |

### Transport transparency

Plugins never import transport implementations directly. They use `MessageBus` interface:

```python
# Correct — plugin uses the interface
from pwnproxy.shared.bus import MessageBus

class MyPlugin(ScannerPlugin):
    def __init__(self, bus: MessageBus):
        self._bus = bus

    async def on_flow(self, flow):
        finding = await self._scan(flow)
        await self._bus.publish("finding.new", finding)
```

The bus is wired in `start.py` with the appropriate transport (InProcessBus for single-process, TcpBridge + InProcessBus for subprocess proxy). Plugins do not know which transport is in use.

### Legacy HookBus compatibility

The existing `HookBus` is bridged from the `MessageBus` via the `_on_proxy_event` callback in `start.py`. Plugins still using `HookBus` continue to work. New plugins SHOULD use `MessageBus` directly.

Migration path:
1. Accept `MessageBus` in constructor (fall back to HookBus if not provided)
2. Replace `self.hook_bus.publish("flow", ...)` with `self._bus.publish("proxy.flow", ...)`
3. Replace `self.hook_bus.register("finding")` with `self._bus.subscribe("finding.new")`

### Topic naming

- Built-in topics use two-part names: `proxy.flow`, `finding.new`, `scan.request`
- Third-party plugins SHOULD prefix with their plugin name: `myplugin.*`
- Topics are lowercase, dot-separated

---

## 10.1c: Scanner architecture – DetectionChain + stages pattern

A **scanner** is composed of a `DetectionChain` (`plugins/core/chain.py`) that orchestrates an ordered list of `DetectionStage` objects. Stages live in `shared/scan/stages/`, each implementing one detection technique.

```python
# plugins/core/chain.py
class DetectionStage(ABC):
    order: int = 0
    min_depth: DetectionDepth = DetectionDepth.FAST
    capability: str = ""

    @abstractmethod
    async def execute(self, flow: Flow, injection_points: List[InjectionPoint]) -> StageResult:
        ...

class DetectionChain:
    def __init__(self, stages: List[DetectionStage], depth: DetectionDepth = DetectionDepth.FAST):
        self.stages = sorted(stages, key=lambda s: s.order)
        self.depth = depth

    async def run(self, flow: Flow, injection_points: List[InjectionPoint]) -> AsyncGenerator[Finding, None]:
        confirmed_keys: set[tuple] = set()
        for stage in self.stages:
            if not stage.should_run(self.depth):
                continue
            remaining = [p for p in injection_points if p.key not in confirmed_keys]
            if not remaining:
                break
            result = await stage.execute(flow, remaining)
            for finding in result.findings:
                yield finding
            confirmed_keys.update(result.confirmed_points)
```

### Stage Constructor Injection

Scanner-specific data (error signatures, payload lists) is **injected** into stages at chain-build time, not imported at module level. This keeps `shared/` free of `plugins/` dependencies.

```python
# shared/scan/stages/sqli_stages.py — stage recibe datos
from plugins.core.chain import DetectionDepth, DetectionStage, StageResult

class ErrorBasedStage(DetectionStage):
    order = 0
    min_depth = DetectionDepth.FAST

    def __init__(self, replayer, signatures: dict, error_payloads: list, evasion_level="none"):
        self._signatures = signatures     # ← inyectado, no importado
        self._error_payloads = error_payloads
        ...

# plugins/scanners/sqli/ — plugin construye el chain con datos inyectados
from .signatures import ERROR_SIGNATURES
from .payloads import get_error_payloads, TIME_PAYLOADS

chain = DetectionChain([
    ErrorBasedStage(replayer, ERROR_SIGNATURES, get_error_payloads()),
    BooleanBlindStage(replayer),
    TimeBlindStage(replayer, TIME_PAYLOADS),
    OOBStage(replayer),
], DetectionDepth(depth))
```

### Result shape

Each stage returns a `StageResult` containing:
- `findings`: list of `Finding` objects discovered by this stage
- `confirmed_points`: set of `InjectionPoint.key` tuples proven vulnerable (subsequent stages skip these points)

### BudgetChain — automatic wave escalation

`BudgetChain` extends `DetectionChain` with automatic depth escalation. It runs stages in budgeted waves (FAST → STANDARD → DEEP), escalating only when:

- No findings were produced in the current wave
- Unconfirmed injection points remain
- The time budget has not been exhausted

```python
from pwnproxy.plugins.core.chain import BudgetChain, DetectionDepth

chain = BudgetChain(
    stages=[
        ErrorBasedStage(replayer, signatures, payloads),
        BooleanBlindStage(replayer),
        TimeBlindStage(replayer, time_payloads),
        OOBStage(replayer),
    ],
    depth=DetectionDepth.STANDARD,
    budget_ms=30000,  # stop after 30s total
)
```

| Wave | Depth | Stages | Budget |
|------|-------|--------|--------|
| 1 | FAST | Error-based only | 3s |
| 2 | STANDARD | Boolean + Time-based | 15s |
| 3 | DEEP | OOB | 30s |

The `chain_from_depth()` helper creates a BudgetChain from a legacy depth string:

```python
chain = chain_from_depth(stages, depth="standard")
# maps to budget_ms=15000 automatically
```

The `budget_ms` parameter is also accepted in scan trigger endpoints (`POST /scanners/trigger-flow` and `POST /scanners/trigger`).

---

## 10.1d: WAF evasion system

The `RequestReplayer` (`shared/scan/replayer.py`) sends HTTP requests to the target. It accepts an **evasion level** which applies transformation functions defined in `shared/scan/evasion.py` before sending.

```python
class RequestReplayer:
    def __init__(self):
        self._client = httpx.AsyncClient(verify=False, follow_redirects=False)
        self._global_semaphore = asyncio.Semaphore(5)

    async def replay(self, point: InjectionPoint, payload: str, timeout=5.0, evasion_level="none") -> httpx.Response | None:
        # builds request with payload injected at point location
        # applies evasion transforms based on level
        # respects rate limiting (global + per-host semaphores)
        ...
```

### Levels
| Level | Transforms applied |
|-------|-------------------|
| `none` | No change |
| `light` | Header case‑randomisation, simple whitespace padding |
| `medium` | URL‑encoding tricks, add harmless comments, chunked encoding |
| `heavy` | Double‑encode, request smuggling tricks, random IV in encrypted payloads |

**Adding a new evasion** – create a function with the signature `def my_transform(req: httpx.Request) -> httpx.Request` and add it to the appropriate list in `EVASION_TRANSFORMS`.

### Replayer lifecycle

The replayer is **created once** in the scanner's `on_load()` and **closed** in `on_unload()`. It is shared across all stages via reference:

```python
class SQLiScannerPlugin(ScannerPlugin):
    async def on_load(self):
        self._replayer = RequestReplayer()        # creado una vez
        self._scanner = SQLiScanner(self._replayer, ...)

    async def on_unload(self):
        await self._replayer.close()              # limpieza
```

---

## 10.1e: Out‑of‑Band (OOB) callback system

Many scanners need a **blind** verification channel. The framework provides a central OOB service.

- **`CanaryRegistry`** (`shared/canary.py`) creates unique URLs or sub‑domains that resolve to the proxy’s callback listeners.
- **Callback servers** – `HTTPCallbackServer` and `DNSCallbackServer` (`shared/http_server.py`) listen on configurable ports and populate the registry when a canary is hit.
- **`OOBStage`** pattern (found in each scanner’s stage module) follows the steps:
  1. `canary = CanaryRegistry.create()`
  2. Inject the canary into payloads.
  3. Wait for `await CanaryRegistry.wait(canary, timeout=5)`
  4. If hit, produce a confirmed `Finding`.

All scanners share the same infrastructure; the callback servers are started once by `plugins/core/startup.py` when the proxy boots.

---

## 10.1f: Folder structure inside pwnproxy folder
```
pwnproxy/                   # pwnproxy folder package
├── plugins/
    ├── core/               # plugin framework
    │   ├── base.py         # abstract PluginBase, ScannerPlugin, HookPlugin
    │   ├── loader.py       # UniversalPluginLoader implementation
    │   ├── watchdog.py     # hot‑reload support during dev
    │   ├── config.py       # plugin‑specific configuration handling
    │   ├── discovery.py    # filesystem & PyPI discovery logic
    │   └── chain.py        # DetectionChain helper used by scanners
    ├── scanners/           # concrete scanner implementations
    │   ├── sqli/           # SQLi scanner
    │   │   ├── scanner.py  # SQLiScanner — builds DetectionChain in __init__
    │   │   ├── plugin.py   # SQLiScannerPlugin — on_load constructs chain with injected data
    │   │   ├── signatures.py # ERROR_SIGNATURES dict (mapa DBMS → regex patterns)
    │   │   ├── payloads.py # Payload dataclass, ERROR_PAYLOADS, TIME_PAYLOADS
    │   │   └── params.py   # legacy extraction helpers
    │   ├── xss/
    │   ├── lfi/
    │   │   ├── signatures.py # LFI_SIGNATURES + OsSignatureMatcher class
    │   │   └── payloads.py
    │   ├── xxe/
    │   └── ssrf/
    ├── exploiters/         # exploiter plugins
    ├── crawlers/           # crawler plugins
    └── ARCHITECTURE.md    # <-- you are reading this file

    shared/scan/            # core scanning utilities used by all scanner plugins
    ├── stages/            # stage implementations (reciben datos inyectados, no importan)
    │   ├── sqli_stages.py # ErrorBasedStage, BooleanBlindStage, TimeBlindStage, OOBStage
    │   ├── xss_stages.py  # ReflectedStage, StoredStage, ContextAwareStage
    │   ├── lfi_stages.py  # SimpleStage, PHPWrapperStage, LfiOOBStage
    │   ├── xxe_stages.py  # XxeErrorBasedStage, JSONMutateStage, XxeOOBStage
    │   └── ssrf_stages.py # SsrfSimpleStage, RedirectStage, SsrfOOBStage
    ├── replayers/         # protocol‑specific request replayers (e.g., XML for XXE)
    │   └── xxe.py
    ├── replayer.py        # generic RequestReplayer base class
    ├── protocols.py       # ``XMLMutableReplayer`` protocol definition
    ├── params.py          # ``InjectionPoint`` and extraction helpers
    ├── rate_limiter.py    # shared RateLimiter used by all plugins
    ├── evasion.py         # evasion transform definitions
    └── payload_store.py   # static payload collections

    shared/                # cross‑cutting utilities
    ├── canary.py          # CanaryRegistry implementation
    ├── http_server.py     # HTTPCallbackServer & DNSCallbackServer
    ├── hooks.py           # HookBus for future HookPlugin interaction
    └── findings/          # FindingORM + FindingStorage (unified findings table)
        └── storage.py
```

---

## 10.1g: Best practices

| Area | Recommendation |
|------|----------------|
| **Rate limiting** | Use the singleton `RateLimiter` from `shared.scan.rate_limiter` instead of creating per‑scanner timers. |
| **Deduplication** | Let the `DetectionChain` maintain a `confirmed_points` set; stages should only emit findings for new points. |
| **Finding publishing** | Stages `yield` findings; the chain collects them and calls `await self.publish(finding)` which forwards to `TaskStore` and the WebSocket event bus. |
| **Error handling** | Wrap stage logic in `try/except` and log the exception; return an empty `StageResult` so the chain continues. |
| **Boilerplate** | Re‑use `shared.scan.params.InjectionPoint`, `shared.scan.evasion.RequestReplayer`, and the OOB helpers instead of re‑implementing them. |

---

## 10.1h: Step‑by‑step guide to create a new scanner plugin

1. **Create the plugin folder**
   ```bash
   mkdir -p plugins/scanners/myvuln
   ```

2. **Define scanner data** – `plugins/scanners/myvuln/payloads.py` (and optionally `signatures.py` if error-based detection)
   ```python
   from dataclasses import dataclass
   
   @dataclass
   class Payload:
       value: str
       technique: str
       dbms: str | None = None
   
   MYVULN_PAYLOADS = [
       Payload("' OR 1=1--", "error-based", "mysql"),
       Payload("' OR '1'='1", "error-based", "mysql"),
   ]
   ```

3. **Write stage implementations** in `shared/scan/stages/` (o en el plugin si son específicas)
   ```python
   # shared/scan/stages/myvuln_stages.py
   from pwnproxy.plugins.core.chain import DetectionStage, StageResult, DetectionDepth
   from pwnproxy.shared.scan.params import InjectionPoint
   from pwnproxy.shared.scan.replayer import RequestReplayer
   from pwnproxy.shared.models import Flow
   from pwnproxy.plugins.core.base import Finding
   
   class MyVulnStage(DetectionStage):
       order = 0
       min_depth = DetectionDepth.FAST
       capability = "myvuln-detection"
   
       def __init__(self, replayer: RequestReplayer, payloads: list, evasion_level="none"):
           self._replayer = replayer
           self._payloads = payloads          # ← inyectado por el scanner
           self._evasion = evasion_level
   
       async def execute(self, flow, injection_points) -> StageResult:
           findings = []
           confirmed = set()
           for point in injection_points:
               for payload in self._payloads:
                   resp = await self._replayer.replay(point, payload.value, evasion_level=self._evasion)
                   if resp and self._is_vulnerable(resp):
                       findings.append(Finding(...))
                       confirmed.add(point.key)
                       break
           return StageResult(findings=findings, confirmed_points=confirmed)
   ```

4. **Create the scanner** – `plugins/scanners/myvuln/scanner.py`
   ```python
   from collections.abc import AsyncGenerator
   from pwnproxy.plugins.core.base import Finding
   from pwnproxy.plugins.core.chain import DetectionChain, DetectionDepth
   from pwnproxy.shared.scan.stages.myvuln_stages import MyVulnStage
   from pwnproxy.shared.scan.replayer import RequestReplayer
   from pwnproxy.shared.scan.params import InjectionPoint
   from pwnproxy.shared.models import Flow
   
   class MyVulnScanner:
       def __init__(self, replayer: RequestReplayer, depth="fast", evasion="none"):
           self._chain = DetectionChain([
               MyVulnStage(replayer, MYVULN_PAYLOADS, evasion),
           ], DetectionDepth(depth))
   
       async def _scan_point(self, point: InjectionPoint) -> AsyncGenerator[Finding, None]:
           flow = Flow(id=point.flow_id, method=point.method, url=point.url, ...)
           async for finding in self._chain.run(flow, [point]):
               yield finding
   ```

5. **Define the plugin class** – `plugins/scanners/myvuln/plugin.py`
   ```python
   from collections.abc import AsyncGenerator
   from pwnproxy.shared.models import Flow
   from pwnproxy.shared.scan.replayer import RequestReplayer
   from pwnproxy.shared.scan.params import extract as extract_params
   from pwnproxy.plugins.core.base import PluginMetadata, ScannerPlugin, Finding
   from pwnproxy.plugins.scanners.myvuln.scanner import MyVulnScanner
   
   class MyVulnPlugin(ScannerPlugin):
       metadata = PluginMetadata(
           name="myvuln",
           version="0.1.0",
           description="Detects MyVuln via payload injection",
           consumes=["flow"],
           produces=["finding"],
       )
   
       async def on_load(self):
           depth = self.context.config.get("depth", "fast")
           evasion = self.context.config.get("evasion_level", "none")
           self._replayer = RequestReplayer()
           self._scanner = MyVulnScanner(self._replayer, depth, evasion)
   
       async def on_flow(self, flow: Flow) -> AsyncGenerator[Finding, None]:
           points = extract_params(flow)
           seen = set()
           for point in points:
               key = (point.host + point.path, point.name, point.location)
               if key in seen:
                   continue
               seen.add(key)
               async for finding in self._scanner._scan_point(point):
                   yield finding
   
       async def on_unload(self):
           await self._replayer.close()
   ```

6. **Register in `apps/terminal/cli/start.py`** alongside other built-in scanners
7. **Write tests** – place them under `tests/scanners/myvuln/`. Test that `_scan_point` yields `Finding` objects when the replayer returns vulnerable responses.
8. **Run the full test suite**:
   ```powershell
   poetry run pytest -q tests/
   ```

Following this pattern guarantees that the new scanner:
- Avoids the `shared → plugins` dependency (data is injected, not imported)
- Builds its detection chain once in `on_load` (not per flow)
- Shares the global rate‑limiter via `RequestReplayer`
- Automatically participates in the OOB callback infrastructure
- Integrates with the unified finding storage (`FindingORM` + `FindingStorage`)

---

*Document generated by the architecture team on $(Get-Date -Format "yyyy‑MM‑dd").*

## Known Issues

### WS events: UnboundLocalError on payload

In `pwnproxy/transport/ws/events.py:154`, `payload` is used but only assigned when `result` is a `dict`. If `result` is `None` or another type, `UnboundLocalError` is raised.

**Fix:** Add `else: payload = json.dumps({"type": "unknown", "data": str(result)}, default=str)` before line 154.