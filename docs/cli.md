# CLI Reference

pwnproxy ships a Typer CLI. Run `pwnproxy --help` for the full command tree.

## pwnproxy start

Start the proxy server and API control plane.

```bash
pwnproxy start --proxy-port 17170 --api-port 17171
```

| Option | Default | Description |
|--------|---------|-------------|
| `--proxy-port` | `17170` | Proxy listen port |
| `--api-port` | `17171` | API server port |
| `--tui` | — | Launch the TUI dashboard |
| `--no-tui` | — | Run without TUI (default) |
| `--host` | `127.0.0.1` | Bind address for both proxy and API |
| `--upstream` | — | Upstream proxy URL (`socks5://host:port` or `http://host:port`) |
| `--session` | — | Load an existing session on boot |
| `--session-name` | — | Create and activate a new session on boot |
| `--no-restore-session` | — | Start with empty state, do not restore last session |
| `--callback-port` | `17173` | Port for the SSRF callback server |

Output on start:

```
Session: default
Proxy    → http://127.0.0.1:17170
API      → http://127.0.0.1:17171
API Docs → http://127.0.0.1:17171/docs
API token → /home/you/.pwnproxy/api-token
Web UI   → http://127.0.0.1:17172/#token=<token>
```

The Web UI line is the one to open: the token travels in the fragment, which the browser never sends
to a server. The token appears in no other line; every other line prints the file path.

With `PWNPROXY_API_TOKEN` set the server accepts that value and ignores the file, so the panel prints
the bare URL plus a note naming the variable (never its value):

```
Web UI   → http://127.0.0.1:17172/
token: PWNPROXY_API_TOKEN (from the environment; ask whoever set it)
```

Press `Ctrl+C` to stop both servers gracefully.

## pwnproxy api token

Show the token the local API asks for, or rotate it.

```bash
pwnproxy api token
```

```text
Token:   Xq7Zk3Lm9Rt2Vw5Yb8Nc1Df4Gh6Jk0Pn3Qs5Tu7AaBb
File:    /home/you/.pwnproxy/api-token
Web UI:  http://127.0.0.1:17172/#token=Xq7Zk3Lm9Rt2Vw5Yb8Nc1Df4Gh6Jk0Pn3Qs5Tu7AaBb
```

| Option | Default | Description |
|--------|---------|-------------|
| `--scope` | `api` | `api` → `api-token` (scope `full`: Web UI, TUI, CLI); `agent` → `mcp-token` (scope `agent`: MCP) |
| `--rotate` | — | Write a new token for the selected scope |

Plain text, one field per line, no wrapping — that is what `dev.ps1`/`dev.sh` parse. To keep only
the token: `pwnproxy api token | sed -n 's/^Token:[[:space:]]*//p'`.

- Both files are created by the API on its first start. If `api-token` does not exist yet, this
  command creates it with the same restricted permissions and adds a `Note:` line saying so.
- `--scope agent` prints `mcp-token` and no Web UI URL. It does **not** create the file: only
  `pwnproxy start` does, so a UI command does not hand out agent credentials. Missing file → exit
  `1` with the instruction to start the API once.
- With `PWNPROXY_API_TOKEN` set it prints that value and
  `Source:  PWNPROXY_API_TOKEN (this value wins over <file>)`. `--rotate` then refuses for the `api`
  scope (exit `1`, nothing written) because the server would keep accepting the variable; the
  `agent` scope still rotates.
- `--rotate` output:

```text
Rotated: /home/you/.pwnproxy/api-token
Token:   <new token>
Old clients get 401 on their next request; WebSockets already open keep working until they reconnect.
Web UI:  http://127.0.0.1:17172/#token=<new token>
```

Exit codes: `0` shown or rotated; `1` no agent token yet, or `--rotate` blocked by the variable;
`2` `--scope` is neither `api` nor `agent`.

The server re-reads the file on every request, so the old token stops working on the next request
without a restart. WebSockets already open keep working until they reconnect (then they get `4401`
and the client asks for the token). `PWNPROXY_API_TOKEN` cannot be rotated from outside: change the
variable and restart.

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

### pwnproxy plugin config

Read and write the configuration a plugin publishes (its schema, its settings and its collections).

```bash
# Everything the plugin declares, plus its current values
pwnproxy plugin config show example-checker

# One collection instead of the settings
pwnproxy plugin config show example-checker --collection webhooks

# Write some settings (partial: only the keys named are sent)
pwnproxy plugin config set example-checker environment=staging

# One secret, read from stdin so it does not land in the shell history
printf '%s\n' "$SIGNING_KEY" | pwnproxy plugin config collection update example-checker webhooks app signing_key=-

# Items of a collection
pwnproxy plugin config collection list example-checker webhooks
pwnproxy plugin config collection add example-checker webhooks name=ci url=https://hooks.example.test/ci events=finding,scan
pwnproxy plugin config collection update example-checker webhooks ci events=finding
pwnproxy plugin config collection remove example-checker webhooks ci
```

`pwnproxy plugin config show example-checker`:

```
Plugin:  example-checker
Schema:  version 1
Settings:
  environment: lab
  retries: 1
Collections:
  webhooks: max 5 items
Actions:
  send_test: long-running, scope full
  ping: inline, scope agent
```

A plugin that declares nothing prints `Plugin:  example-checker` and
`Config:  none declared by the plugin`. A secret reads `set` or `unset` — the value never leaves the
plugin, not even to the CLI.

`pwnproxy plugin config set example-checker environment=staging`:

```
Updated example-checker: environment
  environment: staging
  retries: 1
```

`pwnproxy plugin config collection list example-checker webhooks`:

```
Collection: webhooks (2/5)
  app:
    auth_header: unset
    events: finding
    name: app
    signing_key: set
    status: active
    url: https://hooks.example.test/app
  ci:
    auth_header: unset
    events: scan, finding
    name: ci
    signing_key: unset
    status: failing
    url: https://hooks.example.test/ci
```

`collection add` and `collection update` print `Created webhooks/ci` / `Updated webhooks/ci`
followed by that item's block; `collection remove` prints `Removed webhooks/ci`.

**Values.** Every argument is `KEY=VALUE`; the type comes from the schema, so `retries=3` goes as an
integer, `debug=true` as a boolean and `events=finding,scan` as an array (comma-separated). A value
that does not parse exits `1` (`retries: expected an integer, got 'abc'`). `KEY=-` reads **one line**
from stdin, so several `KEY=-` arguments consume one line each, in order:
`printf '%s\n' "$SIGNING_KEY" | pwnproxy plugin config collection update example-checker webhooks app signing_key=-`.

### pwnproxy plugin action

Run an action a plugin declares, and read back a long one.

```bash
# A short action: its result is printed inline
pwnproxy plugin action run example-checker ping name=app

# A long action: it prints the task id and how to read it, and does not block
pwnproxy plugin action run example-checker send_test name=app payload='{"event": "test"}'
pwnproxy plugin action status 9f2c1a4e
```

```
Status:  running
Task:    9f2c1a4e
Read it with: pwnproxy plugin action status 9f2c1a4e
```

```
Status:  completed
Result:
{
  "delivered": true,
  "status_code": 204
}
```

`status` prints the task's `Status:` and, when it failed, `Error:   <message>`; a `Result:` block
follows once the task has one. An action's parameters are `KEY=VALUE` like the rest, and can never be
a secret: an action uses a credential the plugin already stores.

**Exit codes.** `0` success. `1` when the API answers `4xx`/`5xx` (the server's `detail` is printed
on stderr, e.g. the `403` of a secret written with an `agent` token), when the API cannot be reached
(`Cannot reach the pwnproxy API (…) — is it running?`), or when an argument is not `KEY=VALUE` or does
not parse to the declared type.

## pwnproxy import burp

Import Burp Suite configuration.

```bash
pwnproxy import burp --config burp-config.json
```

Imports the target scope (include/exclude URL rules) from a Burp Suite JSON export and writes them to `~/.pwnproxy/burp_scope.json`.
