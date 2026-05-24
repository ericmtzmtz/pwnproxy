<p align="center">
  <img src="https://img.shields.io/badge/python-3.14+-blue.svg" alt="Python 3.14+">
  <img src="https://img.shields.io/badge/license-AGPLv3-blue.svg" alt="AGPL v3">
  <img src="https://img.shields.io/badge/tests-235%20passing-brightgreen.svg" alt="235 tests passing">
</p>

<h1 align="center">pwnproxy</h1>
<p align="center"><strong>Open source Burp Suite alternative for the terminal</strong></p>

pwnproxy is a terminal-native web application security testing toolkit. Built on mitmproxy with a FastAPI control plane and a Typer CLI, it provides intercepting proxy, automated scanning (SQLi, XSS, LFI, XXE, SSRF), session token management, repeater, intruder, and a REST API — all running locally without a GUI or cloud dependency.

---

## Features

- **Intercepting Proxy** — Pause, inspect, edit, and resume HTTP/HTTPS flows in real time with a Textual TUI
- **Automated Scanners** — SQLi (error + time-based blind), XSS (reflected + stored with context-aware payloads), LFI (OS fingerprinting + PHP wrappers), XXE (error-based + OOB + JSON mutation), SSRF (OOB callback detection)
- **Session Manager** — Auto-extract JWT, cookies, and CSRF tokens from proxied traffic; store with dedup by SHA256 hash
- **Repeater** — Send raw HTTP requests and inspect responses, bypassing the proxy
- **Intruder** — Burp-compatible §marker§ fuzzing with Sniper and Cluster Bomb modes
- **REST API** — Full programmatic control over traffic, findings, sessions, interceptor, repeater, and intruder
- **CLI** — Start/stop proxy + API, query history, browse findings, manage sessions
- **3 SQLite Databases** — Persistent storage for traffic (`traffic.db`), scanner results (`scanner_results.db`), and session tokens (`sessions.db`)

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                         pwnproxy                              │
│                                                               │
│  ┌──────────┐    HookBus (asyncio.Queue pub/sub)              │
│  │          │    ┌──────┐ ┌───────┐ ┌───────┐ ┌──────────┐   │
│  │  Proxy   │───▶│request││response││ error ││  done    │   │
│  │ (mitmproxy)│   └──────┘ └───────┘ └───────┘ └──────────┘   │
│  │  Addons  │        │         │        │          │          │
│  │ ┌──────┐ │        ▼         ▼        ▼          ▼          │
│  │ │Hook  │ │   ┌──────────────────────────────────┐          │
│  │ │Relay │ │   │         Consumers                 │          │
│  │ ├──────┤ │   │ ┌────────┐ ┌────────┐ ┌────────┐ │          │
│  │ │Stor- │ │   │ │Scanner │ │Session │ │Inter-  │ │          │
│  │ │age   │ │   │ │(x5)    │ │Manager │ │ceptor  │ │          │
│  │ └──────┘ │   │ └────────┘ └────────┘ └────────┘ │          │
│  └──────────┘   └──────────────────────────────────┘          │
│       │                                                       │
│       ▼                                                       │
│  ┌──────────┐     ┌──────────┐     ┌──────────┐              │
│  │ Repeater │     │ Intruder │     │Session   │              │
│  │ (httpx)  │     │(fuzzer)  │     │Storage   │              │
│  └──────────┘     └──────────┘     └──────────┘              │
│                                                               │
│  ┌──────────────────────────────────────────────────┐          │
│  │          FastAPI Control Plane (:8000)            │          │
│  │  /flows  /findings  /sessions  /interceptor      │          │
│  │  /repeater  /intruder  /scanners  /ws            │          │
│  └──────────────────────────────────────────────────┘          │
│                                                               │
│  ┌──────────────────────────────────────────────────┐          │
│  │          Typer CLI (pwnproxy)                     │          │
│  │  start  history  findings  session                │          │
│  └──────────────────────────────────────────────────┘          │
└──────────────────────────────────────────────────────────────┘
```

---

## Quickstart

```bash
# 1. Install
pip install pwnproxy

# 2. Start proxy + API
pwnproxy start --proxy-port18080 --api-port 8000

# 3. Configure curl to use the proxy
curl -x http://127.0.0.1:8080 http://httpbin.org/get

# 4. View captured traffic
pwnproxy history

# 5. View via API
curl http://127.0.0.1:8000/api/v1/flows
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
pwnproxy start --proxy-port18080 --api-port 8000
```

| Option | Default | Description |
|--------|---------|-------------|
| `--proxy-port` | `8080` | Proxy listen port |
| `--api-port` | `8000` | API server port |

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

---

## API Reference

The API runs on `http://127.0.0.1:8000` by default (configurable via `--api-port`).

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

Available scanners: `sqli`, `xss`, `lfi`, `xxe`, `ssrf`.
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

- **Detection**: Error-based (DOOCTYPE with local file entities, XML parser error detection), XInclude bypass (`<xi:include>` when DOCTYPE blocked), JSON-to-XML mutation (for `application/json` endpoints), OOB (parameter entity callback to configured domain).
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

---

## License

GNU Affero General Public License v3.0. See [LICENSE](./LICENSE) for the full text.
