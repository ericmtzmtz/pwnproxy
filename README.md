<p align="center">
  <img src="https://img.shields.io/badge/python-3.12+-blue.svg" alt="Python 3.12+">
  <img src="https://img.shields.io/badge/license-AGPLv3-blue.svg" alt="AGPL v3">
  <img src="https://img.shields.io/badge/tests-passing-brightgreen.svg" alt="Tests passing">
  <img src="https://img.shields.io/badge/MCP-native-purple.svg" alt="MCP Native">
</p>

<h1 align="center">pwnproxy</h1>

<p align="center">
  <strong>One security testing engine. Every interface.</strong>
</p>

<p align="center">
  An open, local-first security testing platform for pentesters,
  AI agents, CI/CD pipelines, and teams.
</p>

---

## Security testing is no longer a desktop-only workflow

Traditional security tools were designed around a single tester using a desktop interface.

pwnproxy is built around a shared security testing engine that can be controlled through a terminal, TUI, REST API, WebSocket streams, CI/CD pipelines, or AI agents through MCP.

```text
                    ┌─────────────────────┐
                    │    pwnproxy core    │
                    │                     │
                    │ Proxy · Scanners    │
                    │ Repeater · Intruder │
                    │ Sessions · Plugins  │
                    └──────────┬──────────┘
                               │
       ┌───────────┬───────────┼───────────┬───────────┐
       ▼           ▼           ▼           ▼           ▼
      CLI         TUI        REST API   WebSocket      MCP
       │           │           │           │           │
  Pentesters   Pentesters   Automation   Teams      AI Agents
```

The same core is used whether you are manually intercepting traffic, running an automated scan, integrating security checks into CI/CD, or giving an AI agent access to your testing workflow.

## Why pwnproxy?

### Local-first

The proxy, scanners, storage, and automation run on your infrastructure.

No cloud dependency is required for the core testing workflow.

### One engine, multiple interfaces

The CLI, TUI, REST API, WebSocket streams, and MCP server are interfaces to the same underlying system.

You do not need separate tools for manual testing and automation.

### Built for automation

Run scans directly from the command line, consume JSON or SARIF output, and integrate findings into CI/CD pipelines.

### AI-native

pwnproxy exposes its capabilities through a native MCP server so compatible AI agents can interact with the same testing engine used by human operators.

### Extensible

Scanners and hooks use a plugin architecture designed for built-in and third-party extensions.

## Quickstart

### 1. Clone and install

```bash
git clone https://github.com/ericmtzmtz/pwnproxy.git
cd pwnproxy

poetry install
```

Python 3.12 or later is required.

### 2. Start the proxy and API

```bash
poetry run pwnproxy start --proxy-port 8080 --api-port 8000
```

This starts:

- Proxy → `127.0.0.1:8080`
- API → `127.0.0.1:8000`
- Docs → `http://127.0.0.1:8000/docs`

### 3. Send traffic through the proxy

```bash
curl -x http://127.0.0.1:8080 http://httpbin.org/get
```

### 4. Inspect captured traffic

```bash
poetry run pwnproxy history
```

### Or scan a target directly

```bash
poetry run pwnproxy scan url https://example.com \
  --scanners sqli,xss \
  --output sarif \
  --output-file report.sarif
```

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Scan completed, no findings |
| 1 | Scan completed, findings found |
| 2 | Error |

pwnproxy is currently installed from source using Poetry. PyPI packaging is planned for a future release.

## Features

### Intercepting Proxy

Pause, inspect, modify, and resume HTTP/HTTPS traffic.

- mitmproxy-based interception
- Textual TUI
- request and response inspection
- session-aware traffic storage
- REST API access
- real-time event streaming

### Automated Scanners

Built-in scanners currently include:

| Scanner | Detection |
|---|---|
| SQLi | Error-based and time-based blind detection |
| XSS | Reflected and stored XSS with context analysis |
| LFI | Content signatures, traversal, and PHP wrappers |
| XXE | Error-based, XInclude, JSON mutation, and OOB workflows |
| SSRF | Parameter analysis, redirect detection, and callback validation |

Scanners consume captured flows and can also be executed directly in headless mode.

### Repeater

Replay and modify raw HTTP requests independently from the proxy.

Findings preserve request data so detected issues can be manually validated.

### Intruder

Request fuzzing using Burp-style §marker§ positions.

Supported modes include:

- Sniper
- Cluster Bomb

### Directory Discovery

Wordlist-based path and file discovery with:

- built-in wordlists
- custom extensions
- soft-404 detection
- scope enforcement
- live result streaming

### Session Management

Automatically extract and store:

- JWTs
- Cookies
- CSRF tokens

Sessions are isolated and persisted locally.

### Plugin System

Extend pwnproxy with custom scanners and hooks.

Plugins can be:

- built into the core
- installed locally
- distributed as Python packages

The same plugin interface is used for built-in and third-party scanners.

A watchdog tracks plugin failures and can automatically disable repeatedly failing plugins.

## One engine, multiple interfaces

### CLI

Run pwnproxy directly from the terminal.

```bash
pwnproxy start
pwnproxy history
pwnproxy findings
pwnproxy scan url https://example.com
pwnproxy plugin list
pwnproxy session list
```

### TUI

Use an interactive terminal interface for:

- captured traffic
- request interception
- findings
- repeater workflows
- session inspection

### REST API

Control the platform programmatically.

```bash
curl http://127.0.0.1:8000/api/v1/flows
```

The API exposes functionality for:

- proxy lifecycle
- traffic
- findings
- sessions
- scanners
- repeater
- intruder
- plugins
- crawling
- directory discovery

Interactive API documentation is available at:

`http://127.0.0.1:8000/docs`

### WebSocket

Consume real-time events for traffic, findings, crawler activity, and other workflows.

Example streams:

- `/ws/traffic`
- `/ws/findings`
- `/ws/events`

This allows external interfaces and automation systems to react to testing activity in real time.

## Built for AI agents

pwnproxy includes a native MCP server that exposes the testing platform to MCP-compatible agents.

```text
Claude / Copilot / Custom Agent
                │
                ▼
        ┌──────────────┐
        │  MCP Server  │
        └──────┬───────┘
               │
               ▼
        ┌──────────────┐
        │ pwnproxy API │
        └──────┬───────┘
               │
     ┌─────────┼─────────┐
     ▼         ▼         ▼
   Traffic   Findings   Scanners
     │         │         │
     └─────────┼─────────┘
               ▼
        Security workflow
```

Start pwnproxy:

```bash
pwnproxy start
```

Then configure your MCP-compatible agent:

```json
{
  "mcpServers": {
    "pwnproxy": {
      "command": "python",
      "args": [
        "-m",
        "apps.mcp.src.pwnproxy_mcp.server"
      ]
    }
  }
}
```

The MCP server acts as a thin integration layer over the pwnproxy platform.

See:

`docs/mcp.md`

for agent-specific configuration and tool documentation.

## Architecture

```text
                           pwnproxy

                     ┌───────────────┐
                     │  Proxy Layer  │
                     │  mitmproxy    │
                     └───────┬───────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │     HookBus     │
                    │  async events   │
                    └────────┬────────┘
                             │
          ┌──────────────────┼──────────────────┐
          ▼                  ▼                  ▼
       Scanners          Sessions            Plugins
          │                  │                  │
          └──────────────────┼──────────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │  Storage Layer  │
                    │ SQLite / async  │
                    └────────┬────────┘
                             │
                             ▼
        ┌──────────────────────────────────────┐
        │             Control Plane            │
        │                                      │
        │ FastAPI · REST · WebSocket · Events  │
        └──────────────────┬───────────────────┘
                           │
       ┌──────────┬────────┼────────┬──────────┐
       ▼          ▼        ▼        ▼          ▼
      CLI        TUI      REST      WS         MCP
```

pwnproxy is designed so that the core testing workflow is independent from the interface used to control it.

## Coming from Burp Suite?

pwnproxy is not a Burp Suite clone.

Burp Suite remains an excellent tool for GUI-based manual testing.

pwnproxy focuses on a different architecture:

| | Burp Suite | pwnproxy |
|---|---|---|
| Primary model | Desktop application | Shared testing engine |
| Manual testing | GUI | TUI + API interfaces |
| Automation | Extensions / integrations | CLI + REST + SARIF |
| AI agents | External integrations | Native MCP server |
| Plugins | Java ecosystem | Python-based plugins |
| Headless workflows | Limited | Native |
| CI/CD | External tooling | Built-in output and exit codes |
| Local deployment | Yes | Yes |

pwnproxy can also import Burp scope configurations.

```bash
pwnproxy import burp --config burp-config.json
```

See:

`docs/burp-migration.md`

for migration details.

## Headless and CI/CD

Run scans without starting the proxy:

```bash
pwnproxy scan url https://example.com \
  --output sarif \
  --output-file report.sarif
```

Example GitHub Actions workflow:

```yaml
- name: Install pwnproxy
  run: |
    git clone https://github.com/ericmtzmtz/pwnproxy.git
    cd pwnproxy
    pip install poetry
    poetry install

- name: Security scan
  run: |
    cd pwnproxy
    poetry run pwnproxy scan url ${{ matrix.url }} \
      --output sarif \
      --output-file report.sarif
  continue-on-error: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: pwnproxy/report.sarif
```

## Storage

pwnproxy uses local SQLite storage per session.

A session can contain:

```text
~/.pwnproxy/sessions/<session>/
├── traffic.db
├── scanner_results.db
├── sessions.db
└── tasks.db
```

This keeps testing data isolated and portable.

A complete session can be backed up or moved as a directory.

For larger collaborative or infrastructure deployments, the storage layer is designed around SQLAlchemy async abstractions.

## Development

### Run the development environment

Linux / macOS:

```bash
./dev.sh
```

Windows PowerShell:

```powershell
.\dev.ps1
```

This starts:

- Proxy → `:8080`
- API → `:8000`
- Web UI → `:4321`

### Run tests

```bash
poetry run pytest
```

### Development principles

- Python 3.12+
- async/await for I/O-heavy workflows
- type hints on public interfaces
- SQLAlchemy 2.0 async patterns
- avoid blocking the proxy event loop
- shared contracts between subsystems
- deterministic tests and reproducible workflows

See the contribution documentation for architecture and development details.

## Roadmap

### Recently completed

- AI integration layer
- Passive crawler
- Active crawler
- Directory bruteforce
- Soft-404 detection
- Scope validation hardening
- Scanner validation fixtures
- Scanner request reproduction data

### Current priority: HARDENING

Before adding major new features, the current development cycle focuses on architectural stability and consistency.

**P0 — Architecture invariants**

- Single ownership model for shared state
- Formal JobState lifecycle
- Shared canonical contracts
- Deterministic golden E2E workflows

**P1 — Operational resilience**

- Event backpressure and QoS
- Operational observability
- Extended LLM telemetry
- Minimal crawler worker decomposition
- Review of oversized service objects

**P2 — Release discipline**

- Ownership documentation
- Performance baselines
- Changelog
- Upgrade guide
- Migration compatibility

### Post-hardening

- WebSocket rooms
- Comments on flows
- Extended report templates
- AI-assisted finding descriptions
- Self-describing plugin metadata

The goal is to strengthen the platform before continuing to expand its surface area.

## Documentation

| Topic | Documentation |
|---|---|
| Installation | `docs/installation.md` |
| CLI | `docs/cli.md` |
| API | `docs/api.md` |
| MCP | `docs/mcp.md` |
| Architecture | `docs/architecture.md` |
| Plugins | `docs/plugin-architecture.md` |
| Scanners | `docs/scanners.md` |
| Directory Discovery | `docs/directory-bruteforce.md` |
| Burp Migration | `docs/burp-migration.md` |
| Development | `docs/development.md` |

## Contributing

Contributions are welcome.

```bash
git clone https://github.com/ericmtzmtz/pwnproxy.git
cd pwnproxy

poetry install
poetry run pytest
```

Before submitting a pull request:

- Create a feature branch.
- Add or update tests.
- Run the full test suite.
- Keep changes focused on a clear architectural responsibility.
- Document public interfaces when necessary.

Detailed architecture changes and specifications are tracked in:

- `openspec/`
- `openspec/changes/`

## Commercial Support

pwnproxy is maintained by [NEXTECH SOLUTIONS](https://nextechsolutions.mx) — a cybersecurity services company based in Mexico.

The core platform is free and open source under the AGPLv3 license.

Professional services may include:

| Service | Description |
|---|---|
| Security assessments | Professional pentesting engagements and reporting |
| Custom development | Custom scanners, plugins, and integrations |
| Training | Hands-on security and DevSecOps training |
| Automation | Security testing workflows integrated into CI/CD |

For inquiries:

[info@nextechsolutions.mx](mailto:info@nextechsolutions.mx)

[NEXTECH SOLUTIONS](https://nextechsolutions.mx)

## License

pwnproxy is licensed under the GNU Affero General Public License v3.0.

See:

`LICENSE`

You are free to use, modify, and distribute pwnproxy under the terms of the AGPLv3.

<p align="center"> Built for security testing beyond the desktop. </p>
