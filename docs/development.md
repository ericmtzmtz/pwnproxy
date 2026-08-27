# Development

## Setup

```bash
git clone https://github.com/ericmtzmtz/pwnproxy.git
cd pwnproxy
poetry install
```

## Local Development

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

## Running Tests

```bash
poetry run pytest
```

Additional test groups:

```bash
# Golden E2E workflows (deterministic, in-process engines)
poetry run pytest -m golden

# Live tests against real targets (opt-in — hits bWAPP + real LLM API)
$env:PWNPROXY_LIVE=1; poetry run pytest -m live
```

## Code Style

- Python 3.12+ with async/await throughout — never block the proxy event loop
- Type hints on all function signatures
- No comments in implementation code (self-documenting via descriptive names)
- SQLAlchemy 2.0 async style for all database access
- mitmproxy addon methods are synchronous; spawn async work via `asyncio.create_task()`

## Architecture Rules

- **Ownership**: every shared state has a single owner — see [`ownership-matrix.md`](ownership-matrix.md). Violations require justification in the PR.
- **Job state**: job lifecycle changes go through the state machine (`pwnproxy/services/jobs/lifecycle.py`) — never a raw `update_status`.
- **Anti-inflation**: no new abstraction until at least 2 real consumers exist.

## Pull Request Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Make changes with tests
4. Run the full test suite: `poetry run pytest`
5. Submit a PR with a clear description of the change

## Architecture References

For detailed design docs and archived change specifications, see [`openspec/`](../openspec) and [`openspec/changes/archive/`](../openspec/changes/archive/).
