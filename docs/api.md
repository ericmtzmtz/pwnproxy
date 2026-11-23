# API Reference

The API runs on `http://127.0.0.1:17171` by default (configurable via `--api-port`). Interactive docs at `http://127.0.0.1:17171/docs`.

## Proxy Lifecycle

#### Start proxy

```bash
curl -X POST http://127.0.0.1:17171/api/v1/proxy/start
```

#### Stop proxy

```bash
curl -X POST http://127.0.0.1:17171/api/v1/proxy/stop
```

#### Restart proxy

```bash
curl -X POST http://127.0.0.1:17171/api/v1/proxy/restart
```

#### Get proxy status

```bash
curl http://127.0.0.1:17171/api/v1/proxy/status
```

## Traffic (Flows)

#### List flows

```bash
curl http://127.0.0.1:17171/api/v1/flows?limit=50&offset=0
```

#### Get flow by ID

```bash
curl http://127.0.0.1:17171/api/v1/flows/42
```

## Findings

#### List all findings

```bash
curl http://127.0.0.1:17171/api/v1/findings
```

#### Get findings by scanner

```bash
curl http://127.0.0.1:17171/api/v1/findings/sqli?limit=100
```

`scanner` is free text: the names come from the plugin catalog (built-ins plus any
installed plugin), so `GET /api/v1/plugins` is the list of valid values.

#### Publish a finding (external producers)

For a plugin, premium module or script that runs outside the proxy process. The body
takes the fields of `Finding`; unknown fields are rejected.

```bash
curl -X POST http://127.0.0.1:17171/api/v1/findings \
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

**Security.** This endpoint shares the API's lack of authentication. The service binds
to `127.0.0.1` by default; exposing the port outside the machine turns this endpoint
into a way to inject findings into a session (and to read the API). Body and catalog
validation keep garbage out, they are **not** access control: any local process can
publish whatever it wants.

## Plugins

#### List plugins

```bash
curl http://127.0.0.1:17171/api/v1/plugins
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
curl -X POST http://127.0.0.1:17171/api/v1/plugins/sqli/toggle
# {"status": "disabled", "name": "sqli"}
```

The state is **machine-wide** and persisted in `[plugin.activation]` of
`~/.pwnproxy/config.toml` before the call returns; it does not depend on the session.
Codes: `404` the name is not in the catalog; `409` the plugin exists but cannot run
(broken package or failing `on_load`), with the reason; `500` the config file cannot be
written, in which case the in-memory state is left untouched.

## Headless Scan (API)

#### Launch a scan

```bash
curl -X POST "http://127.0.0.1:17171/api/v1/scan?url=https%3A%2F%2Fexample.com%2Fpage%3Fid%3D1&scanners=sqli,xss"
```

#### Poll scan results

```bash
curl http://127.0.0.1:17171/api/v1/scan/<scan_id>
```

## Burp Import (API)

#### Import Burp config

```bash
curl -X POST http://127.0.0.1:17171/api/v1/import/burp \
  -H "Content-Type: multipart/form-data" \
  -F "file=@burp-config.json"
```

## Sessions

#### List sessions

```bash
curl http://127.0.0.1:17171/api/v1/sessions
curl http://127.0.0.1:17171/api/v1/sessions?token_type=jwt
curl http://127.0.0.1:17171/api/v1/sessions?search=example.com
```

#### Get session by ID

```bash
curl http://127.0.0.1:17171/api/v1/sessions/1
```

#### Delete session

```bash
curl -X DELETE http://127.0.0.1:17171/api/v1/sessions/1
```

## Interceptor

#### Get interceptor status

```bash
curl http://127.0.0.1:17171/api/v1/interceptor/status
```

#### Toggle interceptor

```bash
curl -X PUT http://127.0.0.1:17171/api/v1/interceptor/toggle
```

## Repeater

#### Send raw HTTP request

```bash
curl -X POST http://127.0.0.1:17171/api/v1/repeater/send \
  -H "Content-Type: application/json" \
  -d '{
    "raw_request": "GET /get HTTP/1.1\r\nHost: httpbin.org\r\n\r\n"
  }'
```

## Intruder

#### Run fuzzing attack

```bash
curl -X POST http://127.0.0.1:17171/api/v1/intruder/run \
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
  -H "Content-Type: application/json" \
  -d '{"seeds": ["https://target.com/"], "depth": 3}'
```

#### Get crawl status

```bash
curl http://127.0.0.1:17171/api/v1/crawler/status
```

#### Stop crawl

```bash
curl -X POST http://127.0.0.1:17171/api/v1/crawler/stop
```

#### List discovered URLs

```bash
curl http://127.0.0.1:17171/api/v1/discovered
```
