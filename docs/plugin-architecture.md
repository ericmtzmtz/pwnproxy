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
ScannerPlugin.scan(flow, depth, evasion_level)
  └─ extract_params(flow) → list[InjectionPoint]
       └─ for each point: scanner._scan_point(point, depth, evasion_level)
            └─ DetectionChain.run(flow, [point])
                 └─ stages execute in order (error → boolean → time → OOB)
                      └─ replayer.replay(point, payload) → check response
```

### _scan_point Contract

All scanner `_scan_point` methods MUST follow this signature:

```python
async def _scan_point(self, point: InjectionPoint, depth: str = "fast", evasion_level: str = "none") -> AsyncGenerator[Finding, None]:
```

Returns an async generator yielding findings. Old-style scanners (returning None) still work via `PluginLoader` compatibility shim but should migrate to the async generator pattern.

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

### DetectionChain

The chain framework (`plugins/core/chain.py`) orchestrates detection stages. Stages run in order; confirmed injection points are removed from subsequent stages.

Stages import `InjectionPoint` from `shared/scan/params.py`, NOT from `plugins/core/chain.py`.

### Adding a New Scanner

1. Create scanner in `plugins/scanners/<name>/scanner.py` with `_scan_point(self, point, depth, evasion_level) -> AsyncGenerator[Finding, None]`
2. Create plugin in `plugins/scanners/<name>/plugin.py` extending `ScannerPlugin`
3. Wire DetectionChain stages in `_scan_point` for multi-technique detection
4. Register in `apps/terminal/cli/scan.py:_build_scan_loader()`
5. Register in `apps/terminal/cli/start.py` (production loader)
6. Add tests matching existing scanner test patterns

## References

- Plugin base classes: `pwnproxy/plugin/base.py`
- Plugin loader: `pwnproxy/plugin/loader.py`
- API endpoint: `GET /api/v1/plugins`
- OpenSpec proposals: `openspec/changes/scanner-premium-depth/`
