# Architecture

pwnproxy is a local-first security testing platform: one core engine exposed through multiple interfaces (CLI, TUI, REST, WebSocket, MCP).

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

pwnproxy is designed so that the core testing workflow is independent from the interface used to control it.

## Event buses

Two event buses coexist:

- **HookBus** — in-process pub/sub (asyncio queues) for proxy addon events and scanner consumption.
- **TcpBridge** — TCP-based bridge between the main process and the crawler worker subprocess.

See [`message-bus.md`](message-bus.md) for the message bus details and [`flow-filter.md`](flow-filter.md) for dynamic scope filtering.

## State ownership

Every shared state has a single owner. See [`ownership-matrix.md`](ownership-matrix.md) for the canonical owner/writer/reader table and the architecture rule.

## Database Locations

pwnproxy persists **SQLite per session** in `~/.pwnproxy/sessions/<name>/`:

| Database | Location | Content |
|----------|----------|---------|
| Traffic | `~/.pwnproxy/sessions/<name>/traffic.db` | HTTP request/response flows |
| Scanner Results | `~/.pwnproxy/sessions/<name>/scanner_results.db` | Findings from all 5 scanners |
| Sessions | `~/.pwnproxy/sessions/<name>/sessions.db` | Extracted JWT, cookie, and CSRF tokens |
| Tasks | `~/.pwnproxy/sessions/<name>/tasks.db` | Scan/intruder/repeater task records |

Each session is self-contained: copy it whole with `cp -r`; isolation between sessions is by file, not by SQL query.

## Database Scaling

pwnproxy uses **SQLite per session** (`~/.pwnproxy/sessions/<name>/*.db`). This is the right default for individual pentesters and small teams — zero ops, backup-friendly, entire session copies with `cp -r`.

When you need **collaborative multi-user** or **large-scale CI/CD**, swap SQLite for PostgreSQL. SQLAlchemy is the abstraction layer — only the connection URL changes:

```python
# SessionManager._point_engines — current:
traffic_url = f"sqlite+aiosqlite:///{path}/traffic.db"

# Collaborative deployment:
traffic_url = "postgresql+asyncpg://user:pass@host/db?options=-csession.id=X"
```

Session isolation switches from file-per-session to `WHERE session_id = X`. The data model (Flow, Finding, Task) is identical.
