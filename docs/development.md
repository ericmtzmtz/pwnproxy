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

This starts the proxy on `:17170`, API on `:17171`, and Web UI on `:17172`, then polls the health endpoint before showing all URLs. Press `Ctrl+C` to stop everything cleanly.

The API needs a token on every route except `GET /api/v1/health`. Once `/health` answers, the script
reads the token with `pwnproxy api token` and prints the Web UI URL that carries it in the fragment:

```text
  Web UI  -> http://127.0.0.1:17172/#token=<token>
             (open this URL: the token travels in the fragment, never to a server)
```

Only the token is taken from that command's output; the URL is built with the port the script is
using, so a `WEB_PORT` override is respected. The health probe itself is unauthenticated. If the
token cannot be read (old CLI, command failed) the bare URL is printed with a warning and the Web UI
asks for the token by hand. With `PWNPROXY_API_TOKEN` set in the environment, `pwnproxy api token`
returns that value, so the printed URL carries the variable's token.

A Web UI tab opened **before** this change still runs the old code and gets `401` on every request:
reload it, or open the URL the script printed.

pwnproxy always runs from the repo virtualenv (`poetry run pwnproxy`) when `poetry` and
`pyproject.toml` are present. A `pwnproxy` found on `PATH` is only a fallback, announced with a
warning: an editable install outside poetry does not carry the project dependencies
(`aiosqlite`, ...) and dies at import time. Proxy output is written to `.dev-logs/pwnproxy.log`
(plus `.dev-logs/pwnproxy.err.log` on Windows); if the process dies before the API answers, the
last lines of that log are printed instead of a generic error. Use `.\dev.ps1 -Verbose` to keep
the output in the console.

Override ports via environment variables:

```bash
PWNPROXY_PROXY_PORT=9090 PWNPROXY_API_PORT=9000 ./dev.sh
```

To run services individually:

```bash
# Terminal 1: Proxy + API
pwnproxy start --proxy-port 17170 --api-port 17171

# Terminal 2: Web UI
cd apps/web && npm run dev
```

Started this way the UI has no fragment, so it asks for the token: `pwnproxy api token` prints it.

### CORS in the dev environment

The API allows only `http://localhost:17172` and `http://127.0.0.1:17172`. Serving the Web UI from
another origin (an `astro dev` on a different port, or opening the UI from another machine) requires
`CORS_ORIGINS`:

```bash
CORS_ORIGINS="http://192.168.1.93:17172" ./dev.sh
```

`CORS_ORIGINS` is read when the API module is imported, so set it before starting the script.

`dev.ps1` passes the API host from `PWNPROXY_API_HOST` (default `127.0.0.1`), so
`PWNPROXY_API_HOST=0.0.0.0` makes the API reachable from the LAN **with** the token. `dev.sh` does
not change the host: for that, run `pwnproxy start --host 0.0.0.0 --no-restore-session` yourself and
start the UI separately. The transport is plain HTTP, so keep this inside a trusted network or
behind a tunnel.

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
