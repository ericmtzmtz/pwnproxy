# API Reference

The API runs on `http://127.0.0.1:8000` by default (configurable via `--api-port`). Interactive docs at `http://127.0.0.1:8000/docs`.

## Proxy Lifecycle

#### Start proxy

```bash
curl -X POST http://127.0.0.1:8000/api/v1/proxy/start
```

#### Stop proxy

```bash
curl -X POST http://127.0.0.1:8000/api/v1/proxy/stop
```

#### Restart proxy

```bash
curl -X POST http://127.0.0.1:8000/api/v1/proxy/restart
```

#### Get proxy status

```bash
curl http://127.0.0.1:8000/api/v1/proxy/status
```

## Traffic (Flows)

#### List flows

```bash
curl http://127.0.0.1:8000/api/v1/flows?limit=50&offset=0
```

#### Get flow by ID

```bash
curl http://127.0.0.1:8000/api/v1/flows/42
```

## Findings

#### List all findings

```bash
curl http://127.0.0.1:8000/api/v1/findings
```

#### Get findings by scanner

```bash
curl http://127.0.0.1:8000/api/v1/findings/sqli?limit=100
```

Available scanners: `sqli`, `xss`, `lfi`, `xxe`, `ssrf`.

## Plugins

#### List plugins

```bash
curl http://127.0.0.1:8000/api/v1/plugins
```

#### Toggle plugin (enable/disable)

```bash
curl -X POST http://127.0.0.1:8000/api/v1/plugins/sqli/toggle
```

## Headless Scan (API)

#### Launch a scan

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/scan?url=https%3A%2F%2Fexample.com%2Fpage%3Fid%3D1&scanners=sqli,xss"
```

#### Poll scan results

```bash
curl http://127.0.0.1:8000/api/v1/scan/<scan_id>
```

## Burp Import (API)

#### Import Burp config

```bash
curl -X POST http://127.0.0.1:8000/api/v1/import/burp \
  -H "Content-Type: multipart/form-data" \
  -F "file=@burp-config.json"
```

## Sessions

#### List sessions

```bash
curl http://127.0.0.1:8000/api/v1/sessions
curl http://127.0.0.1:8000/api/v1/sessions?token_type=jwt
curl http://127.0.0.1:8000/api/v1/sessions?search=example.com
```

#### Get session by ID

```bash
curl http://127.0.0.1:8000/api/v1/sessions/1
```

#### Delete session

```bash
curl -X DELETE http://127.0.0.1:8000/api/v1/sessions/1
```

## Interceptor

#### Get interceptor status

```bash
curl http://127.0.0.1:8000/api/v1/interceptor/status
```

#### Toggle interceptor

```bash
curl -X PUT http://127.0.0.1:8000/api/v1/interceptor/toggle
```

## Repeater

#### Send raw HTTP request

```bash
curl -X POST http://127.0.0.1:8000/api/v1/repeater/send \
  -H "Content-Type: application/json" \
  -d '{
    "raw_request": "GET /get HTTP/1.1\r\nHost: httpbin.org\r\n\r\n"
  }'
```

## Intruder

#### Run fuzzing attack

```bash
curl -X POST http://127.0.0.1:8000/api/v1/intruder/run \
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
curl -X POST http://127.0.0.1:8000/api/v1/scanners/trigger \
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
ws://127.0.0.1:8000/ws/traffic
# → {"type": "flow", "method": "GET", "url": "...", "id": "...", "status_code": 200}

# Findings stream
ws://127.0.0.1:8000/ws/findings
# → {"type": "finding", "scanner": "sqli", ...}

# Unified events stream (traffic + findings)
ws://127.0.0.1:8000/ws/events

# Room-isolated stream (multi-client team sessions)
ws://127.0.0.1:8000/ws/rooms/{room_id}
```

## Crawler

#### Start active crawl

```bash
curl -X POST http://127.0.0.1:8000/api/v1/crawler/start \
  -H "Content-Type: application/json" \
  -d '{"seeds": ["https://target.com/"], "depth": 3}'
```

#### Get crawl status

```bash
curl http://127.0.0.1:8000/api/v1/crawler/status
```

#### Stop crawl

```bash
curl -X POST http://127.0.0.1:8000/api/v1/crawler/stop
```

#### List discovered URLs

```bash
curl http://127.0.0.1:8000/api/v1/discovered
```
