# CLI Reference

pwnproxy ships a Typer CLI. Run `pwnproxy --help` for the full command tree.

## pwnproxy start

Start the proxy server and API control plane.

```bash
pwnproxy start --proxy-port 8080 --api-port 8000
```

| Option | Default | Description |
|--------|---------|-------------|
| `--proxy-port` | `8080` | Proxy listen port |
| `--api-port` | `8000` | API server port |
| `--tui` | — | Launch the TUI dashboard |
| `--no-tui` | — | Run without TUI (default) |
| `--host` | `127.0.0.1` | Bind address for both proxy and API |
| `--upstream` | — | Upstream proxy URL (`socks5://host:port` or `http://host:port`) |
| `--session` | — | Load an existing session on boot |
| `--session-name` | — | Create and activate a new session on boot |
| `--no-restore-session` | — | Start with empty state, do not restore last session |
| `--callback-port` | `18081` | Port for the SSRF callback server |

Output on start:

```
Session: default
Proxy  → 127.0.0.1:8080  (intercepting)
API    → 127.0.0.1:8000  (http://127.0.0.1:8000/docs)
```

Press `Ctrl+C` to stop both servers gracefully.

## pwnproxy history

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

## pwnproxy findings

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
| `--scanner`, `-s` | `all` | Filter by scanner: `sqli`, `xss`, `lfi`, `xxe`, `ssrf` |
| `--limit`, `-n` | `20` | Max findings to show |

## pwnproxy session

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

## pwnproxy scan url

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

## pwnproxy plugin

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
| `create --template scanner\|hook <name>` | Scaffold a PyPI-ready plugin project |

## pwnproxy import burp

Import Burp Suite configuration.

```bash
pwnproxy import burp --config burp-config.json
```

Imports the target scope (include/exclude URL rules) from a Burp Suite JSON export and writes them to `~/.pwnproxy/burp_scope.json`.
