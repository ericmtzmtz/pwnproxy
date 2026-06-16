<p align="center">
  <img src="https://img.shields.io/badge/python-3.14+-blue.svg" alt="Python 3.14+">
  <img src="https://img.shields.io/badge/license-AGPLv3-blue.svg" alt="AGPL v3">
  <img src="https://img.shields.io/badge/tests-235%20passing-brightgreen.svg" alt="235 tests passing">
  <img src="https://img.shields.io/badge/MCP-native-purple.svg" alt="MCP Native">
</p>

<h1 align="center">pwnproxy</h1>
<p align="center"><strong>The security testing platform built for the AI era.</strong></p>
<p align="center">Plugin architecture &nbsp;·&nbsp; Headless CI/CD &nbsp;·&nbsp; MCP-native AI agent integration &nbsp;·&nbsp; AGPL</p>

<br>

> **→ Pentesters** use the TUI and CLI like Burp — no GUI license required.  
> **→ AI agents and CI/CD pipelines** consume the REST API and MCP server natively.  
> **→ Teams** share live sessions in real time via WebSocket rooms.

pwnproxy is a modular web application security testing platform. Built on mitmproxy with a FastAPI control plane, Typer CLI, and plugin system, it provides intercepting proxy, automated scanning (SQLi, XSS, LFI, XXE, SSRF), session token management, repeater, intruder, a REST API, and an MCP server for AI agent integration — all running locally without a GUI or cloud dependency.

---

## Why pwnproxy

Burp Suite was designed for a single pentester with a GUI.  
pwnproxy was designed for a world where security testing happens in pipelines, AI agents reproduce findings automatically, and teams collaborate in real time.

| | Burp Suite | pwnproxy |
|---|---|---|
| Audience | Manual pentesters | Pentesters + AI agents + CI/CD + teams |
| Plugins | Java BApp Store | `pip install pwnproxy-*` |
| Headless | Workarounds required | Native CLI + REST API |
| AI integration | None | MCP server — Claude, Copilot, custom agents |
| Collaboration | Collaborator (OOB only) | WebSocket rooms, shared sessions |
| Output format | UI-bound, XML/HTML | JSON-first, SARIF, OpenAPI |
| Cost | $449/yr (Pro), $9k+/yr (DAST) | Free, AGPL |

---

## Features

- **Intercepting Proxy** — Pause, inspect, edit, and resume HTTP/HTTPS flows in real time with a Textual TUI
- **Automated Scanners** — SQLi (error + time-based blind), XSS (reflected + stored with context-aware payloads), LFI (OS fingerprinting + PHP wrappers), XXE (error-based + OOB + JSON mutation), SSRF (OOB callback detection)
- **Plugin System** — Extend with custom scanners and hooks via PyPI packages (`pwnproxy-*`); watchdog auto-disables failing plugins
- **Headless CLI** — `pwnproxy scan url <target>` with JSON/SARIF output and CI/CD exit codes
- **MCP Server** — Native Model Context Protocol server for AI agent integration (Claude Desktop, Copilot, custom agents)
- **Burp Import** — Migrate existing Burp scope configurations with `pwnproxy import burp --config <file>`
- **Session Manager** — Auto-extract JWT, cookies, and CSRF tokens from proxied traffic; store with dedup by SHA256 hash
- **Repeater** — Send raw HTTP requests and inspect responses, bypassing the proxy
- **Intruder** — Burp-compatible §marker§ fuzzing with Sniper and Cluster Bomb modes
- **REST API** — Full programmatic control over traffic, findings, sessions, plugins, scanning, and burp import
- **WebSocket** — Real-time traffic and finding streams with room isolation for team collaboration
- **3 SQLite Databases** — Persistent storage for traffic (`traffic.db`), scanner results (`scanner_results.db`), and session tokens (`sessions.db`)

---

## AI Agent Integration (MCP)

pwnproxy ships a native MCP server at `apps/mcp/` — a thin wrapper over the REST API.
Any MCP-compatible agent (Claude, Copilot, custom) can control the proxy, read
traffic/findings, manage sessions, run scans, and export reports.

**Setup:** Start pwnproxy (`pwnproxy start`), then add this to your agent's MCP config:

```json
{
  "mcpServers": {
    "pwnproxy": {
      "command": "python",
      "args": ["-m", "apps.mcp.src.pwnproxy_mcp.server"]
    }
  }
}
```

Where to put it:

| Agent | Config File | Path |
|---|---|---|
| **OpenCode** | `opencode.jsonc` | `~/.config/opencode/opencode.jsonc` — under `"mcpServers"` |
| **Claude Desktop** | `claude_desktop_config.json` | Windows: `%APPDATA%\Claude\` — macOS: `~/Library/Application Support/Claude/` |
| **Cline / Roo** | `cline_mcp_settings.json` | `~/.config/cline/` |
| **Windsurf** | `mcp_config.json` | `.windsurf/` in project root |
| **Continue (VS Code)** | `config.json` | `~/.continue/config.json` under `"experimental.mcpServers"` |

**Custom ports:** Call the `configure` tool with your API URL and session name.
Default: `http://127.0.0.1:8000/api/v1`.

See `docs/mcp.md` for tool reference, workflow examples, and per-agent setup details.

---

## Quickstart

```bash
# 1. Install
pip install pwnproxy

# 2. Start proxy + API
pwnproxy start --proxy-port 8080 --api-port 8000

# 3. Configure curl to use the proxy
curl -x http://127.0.0.1:8080 http://httpbin.org/get

# 4. View captured traffic
pwnproxy history

# 5. View via API
curl http://127.0.0.1:8000/api/v1/flows

# 6. Headless scan (no proxy needed)
pwnproxy scan url https://example.com --output json

# 7. List installed plugins
pwnproxy plugin list
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         pwnproxy                                  │
│                                                                   │
│  ┌──────────┐    HookBus (asyncio.Queue pub/sub)                  │
│  │          │    ┌──────┐ ┌───────┐ ┌───────┐ ┌──────────┐       │
│  │  Proxy   │───▶│request││response││ error ││  done    │       │
│  │(mitmproxy)│   └──────┘ └───────┘ └───────┘ └──────────┘       │
│  │  Addons  │        │         │        │          │              │
│  │ ┌──────┐ │        ▼         ▼        ▼          ▼              │
│  │ │Hook  │ │   ┌──────────────────────────────────────┐          │
│  │ │Relay │ │   │         Consumers                     │          │
│  │ ├──────┤ │   │ ┌────────┐ ┌────────┐ ┌────────────┐ │          │
│  │ │Stor- │ │   │ │ Plugin │ │Session │ │  Plugin    │ │          │
│  │ │age   │ │   │ │ Loader │ │Manager │ │ Watchdog   │ │          │
│  │ └──────┘ │   │ │(scanner│ └────────┘ │(auto-disable│ │          │
│  └──────────┘   │ │ hooks) │            │ after 3× ) │ │          │
│       │         │ └────────┘            └────────────┘ │          │
│       ▼         └──────────────────────────────────────┘          │
│  ┌──────────┐     ┌──────────┐     ┌──────────┐                  │
│  │ Repeater │     │ Intruder │     │Session   │                  │
│  │ (httpx)  │     │(fuzzer)  │     │Storage   │                  │
│  └──────────┘     └──────────┘     └──────────┘                  │
│                                                                   │
│  ┌──────────────────────────────────────────────────────┐          │
│  │          FastAPI Control Plane (:8000)                │          │
│  │  /flows  /findings  /sessions  /interceptor          │          │
│  │  /repeater  /intruder  /scanners  /ws  /plugins      │          │
│  │  /scan  /import                                        │          │
│  └──────────────────────────────────────────────────────┘          │
│                                                                   │
│  ┌──────────────────────────────────────────────────────┐          │
│  │          Typer CLI (pwnproxy)                         │          │
│  │  start  scan  plugin  import  history  findings       │          │
│  └──────────────────────────────────────────────────────┘          │
│                                                                   │
│  ┌──────────────────────────────────────────────────────┐          │
│  │          MCP Server (pwnproxy-mcp — stdio)            │          │
│  │  scan_url  list_findings  get_status                  │          │
│  └──────────────────────────────────────────────────────┘          │
└──────────────────────────────────────────────────────────────────┘
```

---

## Installation

### pip

```bash
pip install pwnproxy
```

Python 3.14 or later required.

### pipx (recommended for CLI tools)

```bash
pipx install pwnproxy
```

### poetry (for development)

```bash
git clone https://github.com/your-org/pwnproxy.git
cd pwnproxy
poetry install
```

---

## Proxy Setup

### curl

```bash
curl -x http://127.0.0.1:8080 http://example.com
```

### Browser

Configure your browser's HTTP proxy to `127.0.0.1:8080`. For HTTPS interception, install the mitmproxy CA certificate (`~/.mitmproxy/mitmproxy-ca-cert.pem`).

### Burp Suite Chaining

1. In Burp Suite, go to **Settings → Network → Connections → Upstream Proxy Servers**
2. Add a rule: Destination host `*`, Proxy host `127.0.0.1`, Port `8080`
3. Ensure Burp's own listener is on a different port (e.g., `:8081`)

---

## CLI Reference

<details>
<summary><strong>pwnproxy start</strong></summary>

Start the proxy server and API control plane.

```bash
pwnproxy start --proxy-port 8080 --api-port 8000
```

| Option | Default | Description |
|--------|---------|-------------|
| `--proxy-port` | `8080` | Proxy listen port |
| `--api-port` | `8000` | API server port |

Output on start:
```
Session: default
Proxy  → 127.0.0.1:8080  (intercepting)
API    → 127.0.0.1:8000  (http://127.0.0.1:8000/docs)
```

Press `Ctrl+C` to stop both servers gracefully.
</details>

<details>
<summary><strong>pwnproxy history</strong></summary>

Query proxy traffic history.

```bash
# List recent flows
pwnproxy history

# Get flow by ID
pwnproxy history get 42
```

| Option | Default | Description |
|--------|---------|-------------|
| `-n`, `--limit` | `10` | Number of flows to show |

Outputs a rich table with ID, method, URL, status code, and timestamp.
</details>

<details>
<summary><strong>pwnproxy findings</strong></summary>

Browse scanner findings.

```bash
# List all findings (grouped by scanner)
pwnproxy findings

# Filter by scanner type
pwnproxy findings --scanner xss

# Limit results
pwnproxy findings --scanner sqli --limit 20
```

| Option | Default | Description |
|--------|---------|-------------|
| `--scanner` | `all` | Filter by scanner: `sqli`, `xss`, `lfi`, `xxe`, `ssrf` |
| `--limit` | `50` | Max findings to show |
</details>

<details>
<summary><strong>pwnproxy session</strong></summary>

Manage stored session tokens.

```bash
# List all tokens
pwnproxy session list

# Filter by type
pwnproxy session list --token-type jwt

# Get token details
pwnproxy session get 1

# Delete a token
pwnproxy session delete 1
```

| Subcommand | Description |
|------------|-------------|
| `list` | List stored tokens (supports `--token-type`, `--search`) |
| `get <id>` | Show full token details |
| `delete <id>` | Remove a token from storage |
</details>

<details>
<summary><strong>pwnproxy scan url</strong></summary>

Headless scan a target URL without starting the proxy.

```bash
# Basic scan
pwnproxy scan url https://example.com

# Specify scanners
pwnproxy scan url https://example.com --scanners sqli,xss

# JSON output to file
pwnproxy scan url https://example.com --output json --output-file results.json

# SARIF output for CI/CD
pwnproxy scan url https://example.com --output sarif --output-file report.sarif
```

| Option | Default | Description |
|--------|---------|-------------|
| `--scanners` | all | Comma-separated scanner filter |
| `--timeout` | `60` | Scan timeout per URL in seconds |
| `--output` | `json` | Output format: `json` or `sarif` |
| `--output-file` | stdout | Write output to file |

**Exit codes**: `0` = no findings, `1` = findings found, `2` = error.

The scan command uses httpx directly (no proxy needed) and returns results in-memory.
</details>

<details>
<summary><strong>pwnproxy plugin</strong></summary>

Manage the plugin system.

```bash
# List loaded + available plugins
pwnproxy plugin list

# Search PyPI for community plugins
pwnproxy plugin search sqli

# Install a plugin from PyPI
pwnproxy plugin install pwnproxy-scanner-my-scanner

# Scaffold a new plugin project
pwnproxy plugin create --template scanner my-scanner
```

| Subcommand | Description |
|------------|-------------|
| `list` | List active and available plugins |
| `search <term>` | Search PyPI for `pwnproxy-*` packages |
| `install <name>` | Install a plugin via pip |
| `create --template scanner|hook <name>` | Scaffold a PyPI-ready plugin project |
</details>

<details>
<summary><strong>pwnproxy import burp</strong></summary>

Import Burp Suite configuration.

```bash
pwnproxy import burp --config burp-config.json
```

Imports the target scope (include/exclude URL rules) from a Burp Suite JSON export and writes them to `~/.pwnproxy/burp_scope.json`.
</details>

---

## Plugin System

pwnproxy's plugin system lets you extend the platform with custom scanners and hooks distributed as PyPI packages.

### Architecture

```
PluginLoader
├── load_builtin(adapter)     # Register a built-in scanner
├── load_plugin(package)      # Load a third-party plugin
├── activate(name)            # Enable a loaded plugin
├── deactivate(name)          # Disable without removing
├── run_scan(flow)            # Run all active ScannerPlugins
├── run_hooks_request(flow)   # Run all active HookPlugins (request)
├── run_hooks_response(flow)  # Run all active HookPlugins (response)
└── list_active()             # Get status of all plugins

PluginWatchdog
├── record_success(name)
├── record_failure(name)      # Auto-disable after 3 consecutive failures
├── stats()                   # Per-plugin failure/success counts
└── reset(name)               # Manual re-enable
```

### Built-in Scanner Plugins

All 5 built-in scanners are registered as `ScannerPlugin` adapters by default. They implement the same interface as third-party plugins — the plugin API has no special cases for built-ins.

### Writing a Scanner Plugin

```python
from pwnproxy.plugin.base import ScannerPlugin, Finding

class MyScanner(ScannerPlugin):
    name = "my-scanner"
    version = "0.1.0"
    author = "you"

    async def scan(self, flow: Flow) -> Finding | None:
        params = self.extract_params(flow)
        for param in params:
            if vulnerable:
                return Finding(
                    scanner=self.name,
                    url=flow.url,
                    method=flow.method,
                    param_name=param.name,
                    param_location=param.location,
                    technique="my-technique",
                    severity="high",
                    confidence="confirmed",
                    payload="<payload>",
                    evidence="<response snippet>",
                )
        return None
```

### Plugin Discovery

Plugins are discovered via:
1. **PyPI** — packages matching `pwnproxy-{category}-{name}` (e.g., `pwnproxy-scanner-xss-ai`)
2. **Local** — installed packages with `pwnproxy` keyword in their metadata
3. **Registry** — optional custom registry URL in `~/.pwnproxy/config.toml`

### Plugin Configuration

```toml
# ~/.pwnproxy/config.toml
[plugin]
plugin_timeout = 30         # Seconds before a plugin times out
watchdog_threshold = 3      # Consecutive failures before auto-disable
registry = "https://..."    # Optional custom registry URL
```

---

## Headless / CI-CD Integration

### Proxy Mode (headless)

```bash
pwnproxy start  # headless by default; no TUI required
# Findings stream as JSON lines to stdout
```

### Scan Mode (no proxy)

```bash
pwnproxy scan url https://example.com --output sarif --output-file report.sarif
```

### GitHub Actions

```yaml
- name: Security scan
  run: |
    pip install pwnproxy
    pwnproxy scan url ${{ matrix.url }} --output sarif --output-file report.sarif
  continue-on-error: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: report.sarif
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed, no findings |
| `1` | Scan completed, findings found |
| `2` | Error (timeout, network, invalid URL) |

---

## Burp Suite Migration

### Importing Scope

1. Export your Burp Suite configuration: **Burp → Settings → Project → Save copy of project file**
2. Or export scope JSON: **Settings → Project → Scope → Copy scope** → save as JSON
3. Import into pwnproxy:

```bash
pwnproxy import burp --config burp-config.json
```

The import extracts:
- **In-scope targets** → pwnproxy scope configuration
- **Excluded targets** → pwnproxy exclusion rules

### What's Not Imported

- BApp / BCheck rules (Java API lock-in, not supported)
- Session handling rules (pwnproxy handles sessions differently)
- Intruder attack definitions (manual replay in pwnproxy intruder)

### Workflow Comparison

| Task | Burp Suite | pwnproxy |
|------|-----------|----------|
| Proxy traffic | Proxy tab | TUI traffic view |
| Manual testing | Repeater | `pwnproxy repeater` |
| Fuzzing | Intruder | `pwnproxy intruder` |
| Scanning | Active/Passive scan | Automated + `pwnproxy scan` |
| Session tokens | Session handler | `pwnproxy session` |
| Plugins | BApp Store (Java) | `pwnproxy plugin install` (Python) |
| AI integration | N/A | `pwnproxy-mcp` MCP server |
| CI/CD | N/A | `pwnproxy scan --output sarif` |

---

## API Reference

The API runs on `http://127.0.0.1:8000` by default (configurable via `--api-port`). Interactive docs at `http://127.0.0.1:8000/docs`.

<details>
<summary><strong>Proxy Lifecycle</strong></summary>

#### Start proxy

```bash
curl -X POST http://127.0.0.1:8000/api/v1/proxy/start
```

#### Stop proxy

```bash
curl -X POST http://127.0.0.1:8000/api/v1/proxy/stop
```

#### Restart proxy

```bash
curl -X POST http://127.0.0.1:8000/api/v1/proxy/restart
```

#### Get proxy status

```bash
curl http://127.0.0.1:8000/api/v1/proxy/status
```
</details>

<details>
<summary><strong>Traffic (Flows)</strong></summary>

#### List flows

```bash
curl http://127.0.0.1:8000/api/v1/flows?limit=50&offset=0
```

#### Get flow by ID

```bash
curl http://127.0.0.1:8000/api/v1/flows/42
```
</details>

<details>
<summary><strong>Findings</strong></summary>

#### List all findings

```bash
curl http://127.0.0.1:8000/api/v1/findings
```

#### Get findings by scanner

```bash
curl http://127.0.0.1:8000/api/v1/findings/sqli?limit=100
```

Available scanners: `sqli`, `xss`, `lfi`, `xxe`, `ssrf`.
</details>

<details>
<summary><strong>Plugins</strong></summary>

#### List plugins

```bash
curl http://127.0.0.1:8000/api/v1/plugins
```

#### Toggle plugin (enable/disable)

```bash
curl -X POST http://127.0.0.1:8000/api/v1/plugins/sqli/toggle
```
</details>

<details>
<summary><strong>Headless Scan (API)</strong></summary>

#### Launch a scan

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "scanners": ["sqli", "xss"]}'
```

#### Poll scan results

```bash
curl http://127.0.0.1:8000/api/v1/scan/<scan_id>
```
</details>

<details>
<summary><strong>Burp Import (API)</strong></summary>

#### Import Burp config

```bash
curl -X POST http://127.0.0.1:8000/api/v1/import/burp \
  -H "Content-Type: multipart/form-data" \
  -F "file=@burp-config.json"
```
</details>

<details>
<summary><strong>Sessions</strong></summary>

#### List sessions

```bash
curl http://127.0.0.1:8000/api/v1/sessions
curl http://127.0.0.1:8000/api/v1/sessions?token_type=jwt
curl http://127.0.0.1:8000/api/v1/sessions?search=example.com
```

#### Get session by ID

```bash
curl http://127.0.0.1:8000/api/v1/sessions/1
```

#### Delete session

```bash
curl -X DELETE http://127.0.0.1:8000/api/v1/sessions/1
```
</details>

<details>
<summary><strong>Interceptor</strong></summary>

#### Get interceptor status

```bash
curl http://127.0.0.1:8000/api/v1/interceptor/status
```

#### Toggle interceptor

```bash
curl -X PUT http://127.0.0.1:8000/api/v1/interceptor/toggle
```
</details>

<details>
<summary><strong>Repeater</strong></summary>

#### Send raw HTTP request

```bash
curl -X POST http://127.0.0.1:8000/api/v1/repeater/send \
  -H "Content-Type: application/json" \
  -d '{
    "raw_request": "GET /get HTTP/1.1\r\nHost: httpbin.org\r\n\r\n"
  }'
```
</details>

<details>
<summary><strong>Intruder</strong></summary>

#### Run fuzzing attack

```bash
curl -X POST http://127.0.0.1:8000/api/v1/intruder/run \
  -H "Content-Type: application/json" \
  -d '{
    "raw_request": "GET /search?q=§fuzz§ HTTP/1.1\r\nHost: example.com\r\n\r\n",
    "mode": "sniper",
    "wordlist_path": "/path/to/wordlist.txt",
    "concurrency": 10,
    "max_results": 100
  }'
```

Supported modes: `sniper` (default), `cluster_bomb`.
</details>

<details>
<summary><strong>Scanners</strong></summary>

#### Trigger scanner on a captured flow

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scanners/trigger \
  -H "Content-Type: application/json" \
  -d '{
    "flow_id": 42,
    "scanners": ["sqli", "xss"]
  }'
```
</details>

<details>
<summary><strong>WebSocket Events</strong></summary>

Real-time event streams for live UIs and team collaboration.

```bash
# Traffic stream
ws://127.0.0.1:8000/ws/traffic
# → {"type": "flow", "method": "GET", "url": "...", "id": "...", "status_code": 200}

# Findings stream
ws://127.0.0.1:8000/ws/findings
# → {"type": "finding", "scanner": "sqli", ...}

# Unified events stream (traffic + findings)
ws://127.0.0.1:8000/ws/events

# Room-isolated stream (multi-client team sessions)
ws://127.0.0.1:8000/ws/rooms/{room_id}
```
</details>

---

## Scanners

All scanners are HookBus consumers: they listen for `"done"` events published by the proxy addon pipeline, extract injection points (query params, form body, JSON body, cookies, headers), and perform automated testing with per-host rate limiting and result dedup.

| Scanner | Detection Methods | Injection Points | Key Features |
|---------|------------------|------------------|--------------|
| **SQLi** | Error-based (5 DBMS), Time-based blind | Query, Form, JSON, Cookies, Headers | DBMS fingerprinting, confirmed/tentative confidence |
| **XSS** | Reflected (probe + canary + context analysis), Stored (canary DB) | Query, Form, JSON, Cookies, Headers | 7 reflection contexts, stored XSS across requests |
| **LFI** | Content-based (OS file signatures) | Query, Form, JSON, Cookies, Headers | OS fingerprinting, PHP wrappers, null byte |
| **XXE** | Error-based, XInclude bypass, JSON mutation, OOB callback | Query, Form, JSON, Cookies, Headers | XML/JSON filtering, DOCTYPE bypass, OOB exfil |
| **SSRF** | OOB callback (internal callback server) | URL-like params, Redirect params | Smart param extraction, redirect detection |

<details>
<summary><strong>SQLi Scanner</strong></summary>

- **Detection**: Error-based using regex signatures for MySQL, PostgreSQL, MSSQL, SQLite, and Oracle. Time-based blind using `SLEEP()`, `pg_sleep()`, `WAITFOR DELAY`, `DBMS_PIPE.RECEIVE_MESSAGE`, and `randomblob()` with latency thresholds (>4s primary, >2.4s confirmation).
- **Injection points**: All 5 locations (query, form body, JSON, cookies, headers).
- **Dedup**: By `(method, host+path, param_name, location)`.
- **Rate limiting**: Global semaphore (5), per-host semaphore (2), 100ms inter-request delay.
</details>

<details>
<summary><strong>XSS Scanner</strong></summary>

- **Detection**: Reflected — probes with `pwnxss-probe`, detects reflection, analyzes context (html_body, html_attr, js_string, url, html_comment, svg_namespace, unknown), and selects context-specific payloads. Stored — injects canaries into SQLite database, scans every response for previously injected canaries.
- **Payload contexts**: `<script>` tags, event handlers, attr breakouts, JS template literals, `javascript:` URIs, `data:` URIs, comment breakouts, SVG `onbegin`/`onload`.
- **Dedup**: By `(method, host+path, param_name, location)`.
</details>

<details>
<summary><strong>LFI Scanner</strong></summary>

- **Detection**: Replays payloads across multiple HTTP methods. Scans response for OS-specific patterns — Unix (`/etc/passwd`, `/bin/bash`), Windows (`win.ini` sections, `boot.ini`), PHP (`php://filter/base64`).
- **Payloads**: Path traversal (`../../../../etc/passwd`), null byte truncation (`%00`), PHP wrappers (`php://filter/read=convert.base64-encode/resource=...`).
- **Dedup**: By `(host+path, param_name, location)`.
</details>

<details>
<summary><strong>XXE Scanner</strong></summary>

- **Detection**: Error-based (DOCTYPE with local file entities, XML parser error detection), XInclude bypass (`<xi:include>` when DOCTYPE blocked), JSON-to-XML mutation (for `application/json` endpoints), OOB (parameter entity callback to configured domain).
- **Scannable content types**: XML (`text/xml`, `application/xml`, etc.) and `application/json`.
- **Dedup**: By `(host+path, param_name, location)`.
</details>

<details>
<summary><strong>SSRF Scanner</strong></summary>

- **Detection**: Smart parameter extraction by name (url, uri, redirect, callback, webhook, fetch, proxy, target, host, domain, page, resource, source) and redirect param detection (params reflected in `Location` headers of 3xx responses). Injects unique canary URLs pointing to an internal `CallbackServer`. A background task polls for hits and escalates severity from low to critical.
- **Infrastructure**: Built-in FastAPI-based callback listener on configurable host:port.
- **Dedup**: By `(host+path, param_name, location)`.
</details>

---

## Database Locations

pwnproxy persists data to three SQLite databases in `~/.pwnproxy/`:

| Database | Location | Contents |
|----------|----------|----------|
| Traffic | `~/.pwnproxy/traffic.db` | HTTP request/response flows |
| Scanner Results | `~/.pwnproxy/scanner_results.db` | Findings from all 5 scanners |
| Sessions | `~/.pwnproxy/sessions.db` | Extracted JWT, cookie, and CSRF tokens |

---

## Contributing

### Setup

```bash
git clone https://github.com/your-org/pwnproxy.git
cd pwnproxy
poetry install
```

### Local Development

Start all services (proxy + API + Web UI) with a single command:

**Linux / macOS:**
```bash
./dev.sh
```

**Windows (PowerShell 7+):**
```powershell
.\dev.ps1
```

This starts the proxy on `:8080`, API on `:8000`, and Web UI on `:4321`, then polls the health endpoint before showing all URLs. Press `Ctrl+C` to stop everything cleanly.

Override ports via environment variables:
```bash
PWNPROXY_PROXY_PORT=9090 PWNPROXY_API_PORT=9000 ./dev.sh
```

To run services individually:
```bash
# Terminal 1: Proxy + API
pwnproxy start --proxy-port 8080 --api-port 8000

# Terminal 2: Web UI
cd web-ui && npm run dev
```

### Running Tests

```bash
poetry run pytest
```

All 235 tests pass.

### Code Style

- Python 3.14+ with async/await throughout — never block the proxy event loop
- Type hints on all function signatures
- No comments in implementation code (self-documenting via descriptive names)
- SQLAlchemy 2.0 async style for all database access
- mitmproxy addon methods are synchronous; spawn async work via `asyncio.create_task()`

### Pull Request Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Make changes with tests
4. Run the full test suite: `poetry run pytest`
5. Submit a PR with a clear description of the change

### Architecture References

For detailed design docs and archived change specifications, see [`openspec/`](./openspec) and [`openspec/changes/archive/`](./openspec/changes/archive/).

### Database Scaling

pwnproxy uses **SQLite per session** (`~/.pwnproxy/sessions/<name>/*.db`). This is the right default for individual pentesters and small teams — zero ops, backup-friendly, entire session copies with `cp -r`.

When you need **collaborative multi-user** or **large-scale CI/CD**, swap SQLite for PostgreSQL. SQLAlchemy is the abstraction layer — only the connection URL changes:

```python
# SessionManager._point_engines — current:
traffic_url = f"sqlite+aiosqlite:///{path}/traffic.db"

# Collaborative deployment:
traffic_url = "postgresql+asyncpg://user:pass@host/db?options=-csession.id=X"
```

Session isolation switches from file-per-session to `WHERE session_id = X`. The data model (Flow, Finding, Task) is identical. See the [enterprise deployment guide](docs/deployment.md) for connection pooling, migration, and multi-tenant configuration.

---

## Roadmap

### 🔴 High Priority

1. **Proxy session-scoped capture** — proxy currently captures all traffic at startup (no session or default session without out-of-scope). On session switch, previously captured traffic persists in the new session. Scope filtering must be enforced at capture time, and traffic must be stored per-session.

2. **Scanner plugins v2 (Premium)** — upgrade all 5 scanner adapters (SQLi, XSS, LFI, XXE, SSRF) to premium tier: advanced payload chains, WAF evasion, blind detection, out-of-band callbacks, second-order injection, and context-aware encoding. Define and document the plugin/module architecture if not already formalized.

3. **Premium Crawler** — Burp-suite-grade crawler with passive mode (extract URLs from proxy traffic matching scope, auto-map directories and files) and active mode (discover hidden endpoints, parameters, and forms). Dedicated page in Web UI.

### 🟡 Medium Priority

4. **Repeater — Render HTML toggle** — raw response view works but the Render HTML button disappeared. Restore it so users can preview rendered responses inline.

5. **Export report — templates + AI** — extend report export with customizable templates (PDF, HTML, Markdown, SARIF) and optional AI-assisted finding descriptions and remediation suggestions.

6. **Self-describing plugin architecture** — ALL plugins (built-in and third-party) MUST expose full metadata via `GET /plugins`: parameters (name, type, required/optional, default, description), capabilities, usage examples, and version. This enables AI agents to auto-discover new plugins and update their SKILL.md/REFERENCE.md without manual intervention. Plugin design doc: `docs/plugin-architecture.md`.

---

## Commercial Support

pwnproxy is maintained by **[NEXTECH SOLUTIONS](https://nextech.mx)** — a cybersecurity services company based in Mexico.

The tool is free and open source under AGPL. NEXTECH offers professional services for organizations that need more than a self-hosted tool:

| Service | Description |
|---|---|
| **Certified pentesting engagements** | Signed reports using pwnproxy for compliance (PCI-DSS, ISO 27001, OWASP) |
| **Custom plugin development** | Scanners and hooks tailored to your specific stack or tech debt |
| **Team training and onboarding** | Hands-on workshops for security and DevSecOps teams |
| **Managed scanning** | Continuous monitoring integrated into your CI/CD pipeline |

Enterprise and government inquiries: **contact@nextech.mx**

---

## License

GNU Affero General Public License v3.0. See [LICENSE](./LICENSE) for the full text.

The AGPL license means: you can use, modify, and distribute pwnproxy freely — including running it as a service — as long as you make the source code available. Commercial use cases that require a different license arrangement can be discussed with NEXTECH SOLUTIONS.