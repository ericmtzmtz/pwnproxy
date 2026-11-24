# API Reference

The API runs on `http://127.0.0.1:17171` by default (configurable via `--api-port`). Interactive docs at `http://127.0.0.1:17171/docs`.

## Authentication

Every route needs `Authorization: Bearer <token>`, except `GET /api/v1/health` and `/docs`.
`OPTIONS` (CORS preflight) is not authenticated either: the browser cannot attach a header there
and it carries no data.

```bash
# POSIX shell: grab only the "Token:" line (the command prints three lines)
TOKEN=$(pwnproxy api token | sed -n 's/^Token:[[:space:]]*//p')

curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:17171/api/v1/flows
```

```powershell
# PowerShell
$TOKEN = (pwnproxy api token | Select-String '^Token:') -replace '^Token:\s+', ''

curl.exe -H "Authorization: Bearer $TOKEN" http://127.0.0.1:17171/api/v1/flows
```

Every example below sends `Authorization: Bearer $TOKEN` unless it says otherwise (only `health`
does).

### Where the tokens live

| File | Scope | Used by |
|---|---|---|
| `<config_dir>/api-token` | `full` | Web UI, TUI, CLI, Docker, scripts |
| `<config_dir>/mcp-token` | `agent` | MCP server |

`<config_dir>` is `PWNPROXY_CONFIG_DIR` when set, otherwise `~/.pwnproxy`. Both files hold the token
and nothing else (no trailing newline) and are restricted to the current user: `0600` on POSIX, a
protected DACL with a single ACE on Windows. If restricting the permissions fails, the API logs a
warning and keeps running: the token still works and refusing to start would be worse.

The API creates both files on its first start (`pwnproxy start` or the Docker container). It never
rotates them on a later start. Deleting them does not reopen the API: with no token anywhere the
answer is `503`, and deleting just one makes the clients using that one get `401`.

`pwnproxy api token` shows the token, the file it came from and the Web UI URL that carries the
token in the fragment (`http://127.0.0.1:17172/#token=<token>`). If the API never ran, the command
creates `api-token` itself. See [`cli.md`](cli.md).

### Status codes

| Code | Body | When |
|---|---|---|
| `401` | `{"detail": "Missing or invalid API token"}` | No header, a scheme other than `Bearer`, or a wrong token |
| `503` | `{"detail": "No API token configured — run 'pwnproxy api token'"}` | No token anywhere: files deleted and no `PWNPROXY_API_TOKEN` |
| `403` | `{"detail": "This token does not grant access to this resource"}` | The route needs a scope the token does not have |

Every `401` and `503` also carries `WWW-Authenticate: Bearer realm="pwnproxy"`. The `401` body is
fixed: it never says "missing" vs "wrong" and never echoes the received value. The check is
`secrets.compare_digest`, never `==`. A rejected request never reaches the route handler.

The `401`/`503` responses keep the CORS headers, so the Web UI can read the status and show the
"paste the token" screen instead of an opaque network error.

### Scopes and `whoami`

| Token | Scope |
|---|---|
| `api-token`, `PWNPROXY_API_TOKEN` | `full` |
| `mcp-token` | `agent` |

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:17171/api/v1/auth/whoami
# {"scope": "full"}
```

`whoami` is how the MCP and the CLI diagnose "wrong token" without guessing. Routes that need
`full` reject an `agent` token with the fixed `403` above. Today those routes are the ones that write
a plugin's declared secret fields and those that run an action declared `requires_scope="full"`
(see [Plugin configuration](#plugin-configuration)); every other route accepts both scopes.

**The honest limit.** The `agent` scope keeps secrets out of the MCP tools, but it does not contain
an agent with a shell on the machine: such an agent can read `~/.pwnproxy/api-token` and get `full`.
To contain an agent, run it on another machine or under another user.

### `PWNPROXY_API_TOKEN`

`PWNPROXY_API_TOKEN` adds a `full` token and wins over `api-token`. The API accepts it **in addition
to** the files and never writes it to disk. Use it in CI and in containers that have no
`~/.pwnproxy`.

```bash
PWNPROXY_API_TOKEN=$(cat /run/secrets/pwnproxy) pwnproxy start
```

With the variable set, `pwnproxy api token` prints its value and the source instead of the file, and
`pwnproxy api token --rotate` refuses to rotate (`api-token` would not be the token in use anyway).
The value is visible to anyone who can read the process environment (`/proc/<pid>/environ`,
`docker inspect`), so do not use it where a file would do.

### Rotation

```bash
pwnproxy api token --rotate              # api-token
pwnproxy api token --rotate --scope agent  # mcp-token
```

The server re-reads the files on every attempt, so a rotated token stops working on the next
request without restarting the API. WebSockets already open survive until they reconnect: the token
was checked during the handshake. The Web UI notices on the next reconnect (close code `4401`) and
asks for the token again. There is no way to rotate `PWNPROXY_API_TOKEN` from outside: change the
variable and restart the API.

### WebSocket

The browser cannot set headers on a `WebSocket`, so the token travels in the subprotocol:

```js
new WebSocket("ws://127.0.0.1:17171/ws/events", ["pwnproxy", "pwnproxy-token." + token]);
```

The server answers the subprotocol `pwnproxy` (never the one carrying the token). Without the
subprotocol, or with an invalid token, it accepts and closes with code `4401` without sending a
message. **The token is never read from the query string** (`?token=…` is ignored): it would end up
in access logs, `Referer` and shell history. A `4401` means "get a token", not "network error".

### CORS

`CORS_ORIGINS` (comma-separated) lists the origins allowed to *read* responses. Default:
`http://localhost:17172,http://127.0.0.1:17172`. Methods: `GET, POST, PUT, PATCH, DELETE, OPTIONS`.
Headers: `Authorization, Content-Type, X-Correlation-ID`; `X-Correlation-ID` is exposed.

There is no `*` and `allow_credentials=False`: authentication is the `Authorization` header, not a
cookie. CORS and the token do different jobs — CORS decides which pages may read the answer, the
token decides who may call. `curl` ignores CORS, so the token is the boundary.

### `/docs` and `/openapi.json`

- `GET /docs` is public and needs no token: it serves Swagger UI with the OpenAPI schema embedded in
  the HTML (no `fetch` to `/openapi.json`). It takes the token from the fragment
  (`http://127.0.0.1:17171/docs#token=<token>`) or from `localStorage`, so "Try it out" works.
- `GET /openapi.json` requires the token. It is the path for tooling:
  `curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:17171/openapi.json | jq`.
- `/redoc` is disabled.

## Proxy Lifecycle

#### Start proxy

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" http://127.0.0.1:17171/api/v1/proxy/start
```

#### Stop proxy

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" http://127.0.0.1:17171/api/v1/proxy/stop
```

#### Restart proxy

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" http://127.0.0.1:17171/api/v1/proxy/restart
```

#### Get proxy status

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:17171/api/v1/proxy/status
```

## Traffic (Flows)

#### List flows

```bash
curl -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:17171/api/v1/flows?limit=50&offset=0"
```

#### Get flow by ID

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:17171/api/v1/flows/42
```

## Findings

#### List all findings

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:17171/api/v1/findings
```

#### Get findings by scanner

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:17171/api/v1/findings/sqli?limit=100
```

`scanner` is free text: the names come from the plugin catalog (built-ins plus any
installed plugin), so `GET /api/v1/plugins` is the list of valid values.

#### Publish a finding (external producers)

For a plugin, premium module or script that runs outside the proxy process. The body
takes the fields of `Finding`; unknown fields are rejected.

```bash
curl -X POST http://127.0.0.1:17171/api/v1/findings \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data @- <<'JSON'
{
  "scanner": "sqli",
  "url": "https://target.local/item?id=1",
  "method": "get",
  "param_name": "id",
  "param_location": "query",
  "technique": "error-based",
  "severity": "high",
  "confidence": "confirmed",
  "payload": "1' OR 1=1-- -",
  "evidence": "SQL syntax error in the response body"
}
JSON
```

Response `201`:

```json
{"id": 17, "scanner": "sqli", "session_id": "acme"}
```

| Field | Required | Notes |
|---|---|---|
| `scanner` | yes | 1-255 chars, must exist in the plugin catalog (enabled or not) |
| `url` | yes | 1-8192 chars |
| `method` | yes | 1-10 chars, stored upper-cased |
| `param_name` | yes | 1-255 chars |
| `param_location` | yes | 1-50 chars, free text (`query`, `body`, `path`, `header`, ...) |
| `technique` | yes | free text |
| `severity` | yes | `low` \| `medium` \| `high` \| `critical` |
| `confidence` | yes | `tentative` \| `inferred` \| `confirmed` |
| `payload` | yes | up to 65 536 chars |
| `evidence` | yes | up to 65 536 chars |
| `timestamp` | no | defaults to now (UTC) |
| `extra` | no | JSON object, up to 65 536 serialized bytes |
| `request_data` | no | JSON object (the triggering request), same size cap |

Codes: `201` saved; `422` invalid field, unknown field, out-of-range size or a
`scanner` that is not in the catalog (the message names it and points at
`GET /api/v1/plugins`); `409` no active session; `500` the storage write failed
(`detail` is always `could not save finding` — the exception goes to the server
log, never into the response body).

The finding is persisted with the same `FindingStorage.save` the internal scanners use
(so the triage callback runs) and only then announced: the stored row is published on
`finding.stored` (the channel `/ws/findings` and `/ws/events` forward, once per finding) and,
for plugins that declare `consumes=["finding"]`, on the raw `finding` channel as before.
**There is no deduplication:** two identical POSTs create two findings.

**Access control.** Any token (`full` or `agent`) can publish: this endpoint is a normal write
route. What protects it is the token, not the body validation — validation keeps garbage out, it is
**not** access control. A token is enough to inject findings into the active session, so treat
`mcp-token` as a write credential for the MCP.

## Plugins

#### List plugins

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:17171/api/v1/plugins
```

```json
{
  "plugins": [
    {"name": "sqli", "source": "builtin", "package": "pwnproxy", "version": "0.3.0",
     "enabled": true, "error": null, "loaded": true, "category": "scanner",
     "description": "", "author": "pwnproxy", "consumes": ["flow"], "produces": ["finding"]},
    {"name": "authorization-matrix", "source": "installed", "package": "pwnproxy-pro",
     "version": "2.0.0", "enabled": false, "error": null, "loaded": false,
     "category": "scanner", "description": "...", "author": "...",
     "consumes": ["flow"], "produces": ["finding"]}
  ],
  "error": null
}
```

- Always `200`; a plugin that failed to import/load is listed with `error` (string) and
  `enabled: false`, never omitted.
- Obligatory fields: `name`, `source` (`builtin` | `installed`), `package`, `version`,
  `enabled`, `error`. Optional: `category`, `description`, `author`, `consumes`,
  `produces`, `loaded`.
- `enabled` is the effective state (config **and** ability to run). Order is stable:
  built-ins first, then `name`.
- Without a live loader the answer is `{"plugins": [], "error": "<reason>"}`.

#### Toggle plugin (enable/disable)

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" http://127.0.0.1:17171/api/v1/plugins/sqli/toggle
# {"status": "disabled", "name": "sqli"}
```

The state is **machine-wide** and persisted in `[plugin.activation]` of
`~/.pwnproxy/config.toml` before the call returns; it does not depend on the session.
Codes: `404` the name is not in the catalog; `409` the plugin exists but cannot run
(broken package or failing `on_load`), with the reason; `500` the config file cannot be
written, in which case the in-memory state is left untouched.

The **body is ignored**: the route flips the current state. There is no `enabled` field to send (a
body carrying `{"enabled": false}` used to be honoured and turned a *disabled* plugin on); read the
result from `GET /api/v1/plugins` after the call.

## Plugin configuration

Every plugin publishes its own configuration schema, and one generic set of routes reads and writes
it. Nothing here is per-plugin: the shape comes from the schema, so a client can paint a form for a
plugin it has never heard of.

| Method | Path | Success | Body |
|---|---|---|---|
| `GET` | `/api/v1/plugins/{name}/schema` | `200` | — |
| `GET` | `/api/v1/plugins/{name}/settings` | `200` | — |
| `PATCH` | `/api/v1/plugins/{name}/settings` | `200` | `{"values": {...}}` (partial) |
| `GET` | `/api/v1/plugins/{name}/collections/{collection}` | `200` | — |
| `POST` | `/api/v1/plugins/{name}/collections/{collection}` | `201` | `{"values": {...}}` |
| `PATCH` | `/api/v1/plugins/{name}/collections/{collection}/{item_id}` | `200` | `{"values": {...}}` (partial) |
| `DELETE` | `/api/v1/plugins/{name}/collections/{collection}/{item_id}` | `204` | — |
| `POST` | `/api/v1/plugins/{name}/actions/{action}` | `200` / `202` | `{"parameters": {...}}` |

A `PATCH` writes only the keys it carries and leaves the rest alone; a `POST` requires every field
the schema marks `required`.

#### Schema

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:17171/api/v1/plugins/example-checker/schema
```

```json
{
  "plugin": "example-checker",
  "schema_version": 1,
  "settings": [
    {"key": "environment", "type": "enum", "required": false, "secret": false,
     "read_only": false, "default": "lab", "choices": ["lab", "staging"],
     "help": "Where the checks run."},
    {"key": "retries", "type": "integer", "required": false, "secret": false,
     "read_only": false, "minimum": 0, "maximum": 5}
  ],
  "collections": [
    {"name": "webhooks", "max_items": 5, "help": "Webhooks the plugin calls.",
     "item": [
       {"key": "name", "type": "string", "required": true, "secret": false,
        "read_only": false, "max_length": 64, "help": "Unique."},
       {"key": "url", "type": "string", "required": true, "secret": false,
        "read_only": false, "max_length": 2048},
       {"key": "events", "type": "array", "required": false, "secret": false,
        "read_only": false, "items": "string", "max_items": 32},
       {"key": "status", "type": "enum", "required": false, "secret": false,
        "read_only": true, "choices": ["active", "failing"],
        "help": "The plugin recomputes it; a client that sends it gets 422."},
       {"key": "signing_key", "type": "string", "required": false, "secret": true,
        "read_only": false, "max_length": 4096},
       {"key": "auth_header", "type": "string", "required": false, "secret": true,
        "read_only": false, "max_length": 4096}
     ]}
  ],
  "actions": [
    {"name": "send_test", "long_running": true, "requires_scope": "full",
     "help": "Sends one test request to a webhook.",
     "parameters": [
       {"key": "name", "type": "string", "required": true, "secret": false,
        "read_only": false},
       {"key": "payload", "type": "string", "required": true, "secret": false,
        "read_only": false, "max_length": 8192}
     ]}
  ]
}
```

- Always `200`, with **empty lists** when the plugin declares no configuration (never a `404`, so a
  client has one code path).
- `key`, `type`, `required`, `secret` and `read_only` are always present; `help` and the
  type-specific attributes (`default`, `choices`, `minimum`, `maximum`, `max_length`, `max_items`,
  `items`) only when declared. Types: `string`, `integer`, `number`, `boolean`, `enum`, `array`.
- The schema is public and never contains a secret *value*: a `secret` field is `string` only and
  cannot declare a `default`.

#### Two shapes, one rule

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:17171/api/v1/plugins/example-checker/settings
```

```json
{"plugin": "example-checker", "schema_version": 1,
 "values": {"environment": {"value": "lab"}, "retries": {"value": 1}}}
```

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:17171/api/v1/plugins/example-checker/collections/webhooks
```

```json
{"plugin": "example-checker", "collection": "webhooks", "schema_version": 1, "max_items": 5,
 "items": [
   {"id": "app", "values": {"name": {"value": "app"},
                            "url": {"value": "https://hooks.example.test/app"},
                            "events": {"value": ["finding"]},
                            "status": {"value": "active"}}},
   {"id": "ci", "values": {"name": {"value": "ci"},
                           "url": {"value": "https://hooks.example.test/ci"},
                           "events": {"value": []},
                           "status": {"value": "failing"},
                           "signing_key": {"set": true}}}
 ]}
```

A non-secret field is `{"value": <json>}`; a `secret` field is `{"set": true|false}`. **No route
returns a secret value**, which is why activating a plugin that holds credentials is a trust
decision: the credential goes in once (Web UI or CLI) and comes out only to the plugin.

#### Writing

```bash
curl -X PATCH -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"values": {"environment": "staging", "retries": 3}}' \
  http://127.0.0.1:17171/api/v1/plugins/example-checker/settings
```

The write answers with the settings again. A declared `secret` is written the same way — a
collection item, `-d '{"values": {"signing_key": "<key>"}}'` — and comes back as `{"set": true}`,
never as a value. An unknown key, a wrong type, a value outside
`choices`/`minimum`/`maximum`/`max_length`/`max_items`, a missing `required` field on a create or a
`read_only` field sent by the client is a `422` from the core; a rule of the plugin (uniqueness,
"webhook names must be unique", …) is a `422` from the plugin, with its own message.

#### Actions

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"parameters": {"name": "app", "payload": "{\"event\": \"test\"}"}}' \
  http://127.0.0.1:17171/api/v1/plugins/example-checker/actions/send_test
# {"plugin": "example-checker", "action": "send_test", "status": "running",
#  "task_id": "9f2c…"}
```

A short action answers `200` with `{"status": "completed", "result": …}`; a `long_running` one
answers `202` with a `task_id` and the result lands in `GET /api/v1/tasks/{task_id}`. Action
parameters can never be `secret`: a long action persists them, so a secret would be at rest outside
the plugin's own store.

#### Codes

| Code | When | `detail` |
|---|---|---|
| `403` | an `agent` token writes a declared secret | `Secret fields can only be written with a token of scope 'full' (Web UI or CLI)` |
| `403` | an `agent` token runs an action that requires `full` | `This token does not grant access to this resource` |
| `404` | unknown plugin, collection, action or item | `plugin '<n>' not found`, `plugin '<n>' declares no collection '<c>'`, `plugin '<n>' declares no action '<a>'`, `plugin '<n>' has no <c> '<id>'` |
| `409` | the plugin cannot be served now | `plugin '<n>' cannot run: <reason>`, `plugin '<n>' declares an invalid … schema`, `plugin '<n>' is not loaded`, `collection '<c>' is full (max <n> items)`, `plugin '<n>' declares no <method>` |
| `422` | the values break a rule | `{"field": "<key or collection.key>", "message": "<rule>"}` |
| `500` | the plugin raised | `plugin '<n>' failed` (the traceback goes to the log only) |
| `503` | the process has no plugin loader, or no task store for a long action | `plugin_loader not available`, `task store not available` |

The secret check runs **before** the body is validated: with an `agent` token the request is refused
without looking at the values, so no `422` can describe a secret.

#### Scope matrix

| Operation | `full` (`api-token`, Web UI, CLI) | `agent` (`mcp-token`, MCP) |
|---|---|---|
| Read the schema, settings or a collection | yes | yes |
| Write a non-secret setting or item field | yes | yes |
| Create or delete an item | yes | yes |
| Write a declared `secret` field | yes | `403` |
| Run an action with `requires_scope="agent"` | yes | yes |
| Run an action with `requires_scope="full"` (the default) | yes | `403` |

An unknown or absent scope fails closed (it is treated as insufficient).

#### Configuration works while the plugin is disabled or its `on_load()` fails; actions do not

A plugin whose `on_load()` fails because of its own configuration — or because an external
requirement is not met yet — would otherwise be impossible to fix outside its own CLI. So reads and
writes build a **disposable** instance from the catalog's factory and never call `on_load()` on it.
The plugin stays **broken** everywhere else: it is not loaded, `GET /api/v1/plugins` reports the same
`error` and `enabled: false`, toggling it still answers `409`, and its actions answer `409`
(`plugin '<n>' cannot run: <reason>`), because an action means "do it now" and a plugin that is off
cannot promise it.

The other failure is different: when the **constructor** raises (or discovery never produced a
factory) there is no instance to ask, so every configuration route answers `409` with the catalog's
reason. A plugin with no configuration contract at all is unaffected: it answers `200` with an empty
schema and empty values, as before.

A write **does not reload** the plugin: the plugin's own `config_write`/`collection_*` persists the
change and applies it to the live state, which is the only seam. Activation stays a separate,
machine-wide flag (`POST /api/v1/plugins/{name}/toggle`), so configuring a plugin never enables it.

#### Audit event

Every **confirmed** write publishes `plugin.config_changed` (QoS `critical`) and logs one line;
`/ws/events` forwards it with the usual envelope:

```json
{"type": "plugin.config_changed", "plugin": "example-checker", "kind": "settings",
 "target": "settings", "item_id": null, "changed": ["environment", "retries"],
 "scope": "full", "timestamp": "2026-11-23T10:00:00+00:00"}
```

`kind` is `settings`, `collection` or `action`; `changed` carries the **names** of the keys written
(empty for a delete or an action) and never a value; a write that failed publishes nothing.

## Headless Scan (API)

#### Launch a scan

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:17171/api/v1/scan?url=https%3A%2F%2Fexample.com%2Fpage%3Fid%3D1&scanners=sqli,xss"
```

#### Poll scan results

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:17171/api/v1/scan/<scan_id>
```

## Burp Import (API)

#### Import Burp config

```bash
curl -X POST http://127.0.0.1:17171/api/v1/import/burp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@burp-config.json"
```

## Sessions

#### List sessions

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:17171/api/v1/sessions
curl -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:17171/api/v1/sessions?token_type=jwt"
curl -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:17171/api/v1/sessions?search=example.com"
```

#### Get session by ID

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:17171/api/v1/sessions/1
```

#### Delete session

```bash
curl -X DELETE -H "Authorization: Bearer $TOKEN" http://127.0.0.1:17171/api/v1/sessions/1
```

## Interceptor

#### Get interceptor status

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:17171/api/v1/interceptor/status
```

#### Toggle interceptor

```bash
curl -X PUT -H "Authorization: Bearer $TOKEN" http://127.0.0.1:17171/api/v1/interceptor/toggle
```

## Repeater

#### Send raw HTTP request

```bash
curl -X POST http://127.0.0.1:17171/api/v1/repeater/send \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "raw_request": "GET /get HTTP/1.1\r\nHost: httpbin.org\r\n\r\n"
  }'
```

## Intruder

#### Run fuzzing attack

```bash
curl -X POST http://127.0.0.1:17171/api/v1/intruder/run \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "raw_request": "GET /search?q=§fuzz§ HTTP/1.1\r\nHost: example.com\r\n\r\n",
    "mode": "sniper",
    "wordlist_path": "/path/to/wordlist.txt",
    "concurrency": 10
  }'
```

Supported modes: `sniper` (default), `cluster_bomb`.

## Scanners

#### Trigger scanner on a captured flow

```bash
curl -X POST http://127.0.0.1:17171/api/v1/scanners/trigger \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "flow_id": 42,
    "scanners": ["sqli", "xss"]
  }'
```

## WebSocket Events

Real-time event streams for live UIs and team collaboration.

```bash
# Traffic stream
ws://127.0.0.1:17171/ws/traffic
# → {"type": "flow", "method": "GET", "url": "...", "id": "...", "status_code": 200}

# Findings stream
ws://127.0.0.1:17171/ws/findings
# → {"type": "finding", "id": 12, "scanner": "sqli", "session_id": "demo", ...}

# Unified events stream (traffic + findings)
ws://127.0.0.1:17171/ws/events

# Room-isolated stream (multi-client team sessions)
ws://127.0.0.1:17171/ws/rooms/{room_id}
```

All four need the token in the subprotocol (`["pwnproxy", "pwnproxy-token.<token>"]`); without it
they close with `4401` before any event is delivered.

Both finding streams forward the **stored row** (the same fields as an item of
`GET /api/v1/findings`, plus `session_id`) published on the bus channel `finding.stored`, so
`id` is always the id in the session database. Findings from a plugin, from a built-in scanner
and from `POST /api/v1/findings` look identical here. A message the relay cannot serialise is
logged and skipped; it never closes the socket. The `findings:{session_id}` room receives the
same row inside the room envelope `{type, session_id, job_id, data}`.

## Crawler

#### Start active crawl

```bash
curl -X POST http://127.0.0.1:17171/api/v1/crawler/start \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"seeds": ["https://target.com/"], "depth": 3}'
```

#### Get crawl status

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:17171/api/v1/crawler/status
```

#### Stop crawl

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" http://127.0.0.1:17171/api/v1/crawler/stop
```

#### List discovered URLs

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:17171/api/v1/discovered
```

## Health

```bash
curl http://127.0.0.1:17171/api/v1/health
```

The only route that needs no token. The dev scripts and the Docker entrypoint probe it.

## Not covered by the token

- The proxy on `17170`: speaking HTTP to it is the point, so it has no credential.
- The SSRF callback on `17173`: the scanned targets call it, so it cannot ask for a token.
- `pwnproxy scan url`: it uses `httpx` against the target and never talks to the API.
