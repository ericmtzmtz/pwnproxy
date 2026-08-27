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
poetry run pwnproxy start --proxy-port 8080 --api-port 8000
```

This starts:

- Proxy → `127.0.0.1:8080`
- API → `127.0.0.1:8000`
- Docs → `http://127.0.0.1:8000/docs`

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
