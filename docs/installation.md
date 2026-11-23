# Installation

## Requirements

- Python 3.12 or later
- [Poetry](https://python-poetry.org/) for dependency management

## Install from source

```bash
git clone https://github.com/ericmtzmtz/pwnproxy.git
cd pwnproxy
poetry install
poetry shell
```

> pwnproxy is not on PyPI yet. Use `poetry run pwnproxy` or `poetry shell` to invoke the CLI. PyPI packaging is planned for a future release.

## Start the proxy and API

```bash
poetry run pwnproxy start --proxy-port 17170 --api-port 17171
```

This starts:

- Proxy → `127.0.0.1:17170`
- API → `127.0.0.1:17171`
- Docs → `http://127.0.0.1:17171/docs`

## First run: the API token

The API requires `Authorization: Bearer <token>` on every route except `GET /api/v1/health`. The
first start creates two files in `~/.pwnproxy` (`PWNPROXY_CONFIG_DIR` overrides the directory), both
readable only by your user:

| File | Scope | Used by |
|---|---|---|
| `api-token` | `full` | Web UI, TUI, CLI, scripts |
| `mcp-token` | `agent` | MCP server |

The startup panel prints the one URL you need, with the token in the fragment:

```text
Web UI   → http://127.0.0.1:17172/#token=<token>
```

Open it: the Web UI stores the token and strips it from the address bar. If you open the UI without
that URL it asks for the token; get it with:

```bash
pwnproxy api token
```

Nothing needs to be configured by hand. `pwnproxy scan url` and the proxy on `17170` do not use the
token.

## Docker

```bash
cd deploy/docker
docker compose up -d --build
```

The token is generated **inside** the container on its first start and lives in the `pwnproxy-data`
volume. Read it and open the UI with it:

```bash
docker compose exec backend cat /data/.pwnproxy/api-token
# -> http://127.0.0.1:17172/#token=<token>

# The MCP gets its own token (scope agent):
docker compose exec backend cat /data/.pwnproxy/mcp-token
```

For a known value (scripted demo, CI) pass `PWNPROXY_API_TOKEN` when starting compose — the line is
commented in `docker-compose.yml` under `environment`. Authentication stays on; only the source
changes, and the value is visible in `docker inspect`.

## The token never goes in a frontend `.env`

`apps/web/.env.example` only holds `PUBLIC_API_BASE` (where the API lives). Anything named
`PUBLIC_*` is embedded in the static bundle at build time, so a token there would be shipped to
every browser. The token is entered at runtime — fragment or the "paste the token" screen — and kept
in `localStorage`.

## Proxy Setup

### curl

```bash
curl -x http://127.0.0.1:17170 http://example.com
```

### Browser

Configure your browser's HTTP proxy to `127.0.0.1:17170`. For HTTPS interception, install the mitmproxy CA certificate (`~/.mitmproxy/mitmproxy-ca-cert.pem`).

### Burp Suite Chaining

1. In Burp Suite, go to **Settings → Network → Connections → Upstream Proxy Servers**
2. Add a rule: Destination host `*`, Proxy host `127.0.0.1`, Port `17170`
3. Ensure Burp's own listener is on a different port (e.g., `:8081`)
