<p align="center">
  <img src="https://img.shields.io/badge/python-3.12+-blue.svg" alt="Python 3.12+">
  <img src="https://img.shields.io/badge/license-AGPLv3-blue.svg" alt="AGPL v3">
  <img src="https://img.shields.io/badge/tests-318%20passing-brightgreen.svg" alt="318 tests passing">
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
- **Directory Bruteforce** — Wordlist-based path discovery with built-in wordlists (small: 368, medium: 3,137, large: 7,780 entries), soft-404 detection, and custom extensions
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
# 1. Clone + install
git clone https://github.com/ericmtzmtz/pwnproxy.git
cd pwnproxy
poetry install

# 2. Start proxy + API
poetry run pwnproxy start --proxy-port 8080 --api-port 8000

# 3. Configure curl to use the proxy
curl -x http://127.0.0.1:8080 http://httpbin.org/get

# 4. View captured traffic
poetry run pwnproxy history

# 5. View via API
curl http://127.0.0.1:8000/api/v1/flows

# 6. Headless scan (no proxy needed)
poetry run pwnproxy scan url https://example.com --output json

# 7. List installed plugins
poetry run pwnproxy plugin list
```

> **Nota:** pwnproxy aún no está publicado en PyPI. Instala desde el repositorio con Poetry. La publicación en PyPI está planeada para una release próxima.

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

### poetry (recomendada)

```bash
git clone https://github.com/ericmtzmtz/pwnproxy.git
cd pwnproxy
poetry install
poetry shell
```

Python 3.12 o posterior requerido.

> pwnproxy aún no está en PyPI. Usa `poetry run pwnproxy` o `poetry shell` para invocar el CLI.

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

# Authenticated scan (session cookies)
pwnproxy scan url "https://example.com/page?id=1" --cookie "PHPSESSID=abc123; security_level=0"

# POST / body-based scan (e.g. XXE)
pwnproxy scan url "https://example.com/xxe" --method POST --data "<reset><login>bee</login></reset>" --content-type "text/xml"

# JSON output to file
pwnproxy scan url https://example.com --output json --output-file results.json

# SARIF output for CI/CD
pwnproxy scan url https://example.com --output sarif --output-file report.sarif
```

| Option | Default | Description |
|--------|---------|-------------|
| `--scanners`, `-s` | all | Comma-separated scanner filter (`sqli`, `xss`, `lfi`, `xxe`, `ssrf`) |
| `--timeout`, `-t` | `60` | Scan timeout per URL in seconds |
| `--output`, `-o` | `json` | Output format: `json`, `sarif`, `html`, `pdf` |
| `--output-file`, `-f` | stdout | Write output to file |
| `--cookie`, `-c` | — | Cookie header for authenticated targets (repeatable) |
| `--header`, `-H` | — | Extra header `Name: Value` (repeatable) |
| `--method`, `-m` | `GET` | HTTP method for the target request (GET, POST, PUT, PATCH) |
| `--data`, `-d` | — | Raw request body (XML, JSON, form) |
| `--content-type` | — | Content-Type header for the body (e.g. `text/xml`) |

**Exit codes**: `0` = no findings, `1` = findings found, `2` = error.

The scan command uses httpx directly (no proxy needed) and returns results in-memory. Findings include `request_data` — the exact payload request — so you can send them to the Repeater for manual validation.
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

## Directory Bruteforce

Wordlist-based path and file discovery via the Web UI or REST API.

### Built-in Wordlists

| Wordlist | Entries | Composition |
|----------|---------|-------------|
| `small` | 368 | Core pentest paths: admin panels, common files, API endpoints, config backups |
| `medium` | 3,137 | Small + combinatorial (roots × suffixes) + framework paths (WordPress, Django, Laravel) + date/number patterns + admin variants + API paths |
| `large` | 7,780 | Medium + Drupal/Joomla/Magento/Exchange/WebLogic/CGI paths + extended combinatorial (only-roots × only-suffixes) |

All wordlists are hand-curated for legal penetration testing. They are **not** exhaustive (no full raft/dirb busting) — for comprehensive discovery, supply your own via the custom wordlist option.

### Features
- **Soft-404 Detection** — Learns custom 404 page signatures by probing random non-existent paths, then filters false positives from results
- **Custom Extensions** — Append `.php`, `.html`, `.txt`, etc. to each wordlist entry
- **Scope Enforcement** — Only tests URLs matching the active session scope
- **Live Results** — Hits appear in real-time in the Discovered URLs dashboard

### API

```bash
# Start bruteforce
curl -X POST http://127.0.0.1:8000/api/v1/bruteforce/start \
  -H 'Content-Type: application/json' \
  -d '{"base_urls": ["https://target.com"], "wordlist": "medium", "detect_soft404": true}'

# List available wordlists
curl http://127.0.0.1:8000/api/v1/bruteforce/wordlists

# Stop
curl -X POST http://127.0.0.1:8000/api/v1/bruteforce/stop
```

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
from pwnproxy.plugins.core.base import ScannerPlugin, Finding

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
- name: Checkout + install
  run: |
    git clone https://github.com/ericmtzmtz/pwnproxy.git
    cd pwnproxy
    pip install poetry
    poetry install

- name: Security scan
  run: |
    poetry run pwnproxy scan url ${{ matrix.url }} --output sarif --output-file report.sarif
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
curl -X POST "http://127.0.0.1:8000/api/v1/scan?url=https%3A%2F%2Fexample.com%2Fpage%3Fid%3D1&scanners=sqli,xss"
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
    "concurrency": 10
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

pwnproxy persiste **SQLite por sesión** en `~/.pwnproxy/sessions/<nombre>/`:

| Database | Ubicación | Contenido |
|----------|-----------|-----------|
| Traffic | `~/.pwnproxy/sessions/<nombre>/traffic.db` | HTTP request/response flows |
| Scanner Results | `~/.pwnproxy/sessions/<nombre>/scanner_results.db` | Findings from all 5 scanners |
| Sessions | `~/.pwnproxy/sessions/<nombre>/sessions.db` | Extracted JWT, cookie, and CSRF tokens |
| Tasks | `~/.pwnproxy/sessions/<nombre>/tasks.db` | Scan/intruder/repeater task records |

Cada sesión es autocontenida: se copia entera con `cp -r` y el aislamiento entre sesiones es por archivo, no por consulta SQL.

---

## Contributing

### Setup

```bash
git clone https://github.com/ericmtzmtz/pwnproxy.git
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
cd apps/web && npm run dev
```

### Running Tests

```bash
poetry run pytest
```

All 318 tests pass (+ 21 MCP server tests in `apps/mcp/tests/`).

### Code Style

- Python 3.12+ with async/await throughout — never block the proxy event loop
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

Session isolation switches from file-per-session to `WHERE session_id = X`. The data model (Flow, Finding, Task) is identical.

---

## Roadmap

### ✅ Recientemente completado

- **Scanner plugins premium** — detection chains escalonadas (error-based → blind → time-based → OOB), WAF evasion, out-of-band callbacks, contexto-aware payloads en los 5 scanners.
- **Repeater rediseñado** — componentes modulares, editor con resaltado HTTP, diff LCS, historial, command palette (Ctrl+K), paneles redimensionables y Render HTML restaurado.
- **Finding request_data** — cada finding guarda el request exacto (URL con payload, headers, body) para validación reproducible en el Repeater.
- **Validación real** — scanners confirmados contra bWAPP (SQLi, LFI, XSS, XXE) y objetivos reales autenticados.

### 🔴 High Priority

1. **Proxy session-scoped capture** — la captura debe respetar el scope de la sesión en tiempo real (no solo al visualizar). Tráfico fuera de scope se descarta al capturarse.

2. **Premium Crawler** — crawler con modo pasivo (extraer URLs del tráfico del proxy filtrando por scope) y activo (descubrir endpoints, parámetros y forms ocultos). Página dedicada en la Web UI.

### 🟡 Medium Priority

3. **Export report — templates + AI** — extender la exportación de reportes con templates personalizables (PDF, HTML, Markdown, SARIF) y descripciones de findings asistidas por IA.

4. **Self-describing plugin architecture** — ALL plugins (built-in y third-party) DEBEN exponer metadata completa vía `GET /plugins`: parámetros, capacidades, ejemplos y versión. Habilita que agentes de IA auto-descubran plugins. Plugin design doc: `docs/plugin-architecture.md`.

---

## Commercial Support

pwnproxy is maintained by **[NEXTECH SOLUTIONS](https://nextechsolutions.mx)** — a cybersecurity services company based in Mexico.

The tool is free and open source under AGPL. NEXTECH offers professional services for organizations that need more than a self-hosted tool:

| Service | Description |
|---|---|
| **Certified pentesting engagements** | Signed reports using pwnproxy for compliance (PCI-DSS, ISO 27001, OWASP) |
| **Custom plugin development** | Scanners and hooks tailored to your specific stack or tech debt |
| **Team training and onboarding** | Hands-on workshops for security and DevSecOps teams |
| **Managed scanning** | Continuous monitoring integrated into your CI/CD pipeline |

Enterprise and government inquiries: **info@nextechsolutions.mx** · [nextechsolutions.mx](https://nextechsolutions.mx)

---

## License

GNU Affero General Public License v3.0. See [LICENSE](./LICENSE) for the full text.

The AGPL license means: you can use, modify, and distribute pwnproxy freely — including running it as a service — as long as you make the source code available. Commercial use cases that require a different license arrangement can be discussed with NEXTECH SOLUTIONS.