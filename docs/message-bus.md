# MessageBus Architecture

## Why

The proxy runs as a subprocess (`proxy_worker.py`) but its events (flows, findings) never reached the main process's `HookBus` — the `EventServer` queue was written but never consumed. Scanners could not see proxied traffic. Each new component (scanners, WS, storage) invented its own communication mechanism. The master roadmap (ADR-004) requires a message queue (Kafka) for H3 — the bus abstraction prevents a rewrite when that migration happens.

## Core Concepts

### MessageBus (ABC)

Defined in `shared/bus/__init__.py`:

```
async def publish(topic: str, data: Any, *, source: str = "") → None
def subscribe(topic: str) → AsyncIterator[Envelope]
```

### Envelope

Every message is wrapped in an `Envelope`:

| Field | Type | Description |
|-------|------|-------------|
| `topic` | `str` | Channel name (e.g. `proxy.flow`) |
| `data` | `Any` | Payload |
| `source` | `str` | Origin identifier |
| `id` | `str` | UUID hex (unique per message) |
| `timestamp` | `datetime` | UTC publication time |

### Standard Topics

| Topic | Producer | Consumer(s) | Payload |
|-------|----------|-------------|---------|
| `proxy.flow` | `proxy_worker.py` | Scanner plugins | `Flow` (as dict over TCP, deserialized at bridge) |
| `finding.new` | Scanner plugins | `FindingStorage`, WS broadcaster | `Finding` |
| `scan.request` | API | Scanner plugins | `ScanRequest` |
| `proxy.status` | `proxy_worker.py` | Health endpoint | heartbeat |

### Topic Naming Convention

- Prefix by source domain: `proxy.*`, `finding.*`, `scan.*`
- Dot-separated: `proxy.flow`, `finding.new`
- Third-party plugins SHOULD prefix with their plugin name

## Transports

### InProcessBus

Implementation in `shared/bus/transports/inprocess.py`:

- asyncio.Queue-based, in-memory delivery
- Single process only
- Zero serialization overhead
- Multiple subscribers on same topic each receive every message
- FIFO ordering per subscriber
- No persistence — unsubscribed messages are lost

Used for: main process internal communication (scanner → storage, scanner → WS).

### TcpBridge

Implementation in `shared/bus/transports/tcp_bridge.py`:

- JSON lines over TCP
- Two sides:
  - **TcpBridgeServer**: runs in `proxy_worker.py`, accepts connections, publishes events
  - **TcpBridgeClient**: runs in main process, connects to server, forwards events to callback
- Auto-reconnect with 1-second backoff on connection loss
- Server publishes to all connected clients; client reconnects if drop detected

Used for: proxy subprocess → main process event forwarding.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  proxy_worker.py (subprocess)                                   │
│                                                                 │
│  mitmproxy                                                      │
│    ├── BridgeRelay (request/response/error → proxy.flow)        │
│    │     └── TcpBridgeServer                                    │
│    └── StorageAddon (flow_stored/done/finding → proxy.*)        │
│          └── BridgeHookBus ──→ TcpBridgeServer                  │
│  (ambos publican al mismo TcpBridgeServer)                      │
│                                       │                         │
└───────────────────────────────────────│─────────────────────────┘
                                        │ TCP / JSON lines
                                        │ (127.0.0.1:random_port)
┌───────────────────────────────────────│─────────────────────────┐
│  main process (API + plugins)         │                         │
│                                       v                         │
│  TcpBridgeClient ──→ _on_proxy_event ──→ HookBus.publish(...)   │
│  (conecta, lee       (deserializa:     (entrega a consumidores) │
│   JSON lines)        distingue topics)                          │
│                                                                  │
│  HookBus consumers:                                              │
│  ├── PluginLoader → ScannerPlugin.on_flow(flow)                  │
│  │     → DetectionChain → Finding                               │
│  │     → publish("finding.new") → FindingStorage.save()         │
│  ├── SessionConsumer (token extraction)                          │
│  └── WS broadcaster (real-time traffic)                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Data Flow (Step by Step)

1. Browser sends request through proxy at `127.0.0.1:8080`
2. mitmproxy (in `proxy_worker.py`) processes the HTTP flow
3. `BridgeRelay.response(f)` is called — converts mitmproxy flow to pwnproxy `Flow` via `Flow.from_mitmproxy(f)`, then serializes to dict via `flow.to_dict()`
4. `TcpBridgeServer.publish("proxy.flow", flow_dict)` sends the dict as JSON line over TCP
4a. `StorageAddon._store_flow()` publishes `flow_stored` and (if auto-scan) `done`
    events via `BridgeHookBus`, which wraps `TcpBridgeServer.publish()` with a `proxy.` topic prefix
4b. `TcpBridgeServer` sends these as JSON lines over the same TCP connection
5. `TcpBridgeClient._run()` receives the line, parses JSON, calls `self._on_event("proxy.flow", data)`
6. `_on_proxy_event()` in `start.py` reconstructs `Flow.from_dict(data)`, then `hook_bus.publish("flow", flow)`
7. `PluginLoader._run_consumer` gets the `Flow` from its HookBus queue, calls `_handle_flow(plugin, flow)`
8. `ScannerPlugin.on_flow(flow)` runs — `extract_params(flow)` finds injection points, `_scan_point()` delegates to `DetectionChain`
9. `DetectionChain` runs stages (ErrorBasedStage, BooleanBlindStage, etc.) which use `RequestReplayer` to send payloads
10. If a Finding is produced, `_publish_results` calls `hook_bus.publish("finding", finding)`
11. `_consume_findings` task receives the Finding and calls `FindingStorage.save(finding)`
12. Finding is now in the session's `scanner_results.db` and visible at `GET /api/v1/findings`

## Migration Path

| Horizon | Transport | Why |
|---------|-----------|-----|
| H1 (today) | InProcessBus + TcpBridge | Zero infra, works for single-tenant |
| H2 (SaaS beta) | Redis pub/sub | Multi-process, shared bus across workers |
| H3 (scale) | Kafka | Partitions by topic, replay, durable, HA |

The migration is transparent to all consumers — only the transport implementation changes.

## Usage

```python
from pwnproxy.shared.bus.transports.inprocess import InProcessBus

bus = InProcessBus()

# Subscribe before publish to avoid race
async for envelope in bus.subscribe("finding.new"):
    finding = envelope.data
    await storage.save(finding)

# Publish
await bus.publish("finding.new", finding)
```

## Testing

```python
bus = InProcessBus()
received = []

async def reader():
    async for e in bus.subscribe("test"):
        received.append(e)

async def writer():
    await asyncio.sleep(0.05)
    await bus.publish("test", {"hello": "world"})

await asyncio.gather(reader(), writer())
assert len(received) == 1
assert received[0].data == {"hello": "world"}
```

## Adding a New Transport

1. Implement `MessageBus` in `shared/bus/transports/<name>.py`
2. Wire it in `start.py` or equivalent entry point
3. Subscribers and publishers do not need changes — they use the same `publish`/`subscribe` interface

## TcpBridge Details

### BridgeHookBus (proxy worker only)

The proxy subprocess (`proxy_worker.py`) does not have a `HookBus` instance. When
`StorageAddon` needs to publish events (e.g., `flow_stored`, `done` findings), it
expects a `hook_bus` object with a `publish(topic, data)` method.

`BridgeHookBus` is an inline class created inside `ProxyWorker.start()` that wraps
the `TcpBridgeServer` to satisfy this interface:

```python
class BridgeHookBus:
    def __init__(self, bridge: TcpBridgeServer):
        self._bridge = bridge
    def publish(self, channel: str, data: dict) -> None:
        asyncio.create_task(self._bridge.publish("proxy." + channel, data))
```

Events published via BridgeHookBus are prefixed with `proxy.` and sent as JSON lines
over TCP, just like BridgeRelay events. The main process receives them through the
same `TcpBridgeClient` and dispatches to `HookBus` via `_on_proxy_event`.


### Server (TcpBridgeServer)

```python
server = TcpBridgeServer(host="127.0.0.1", port=0)  # port=0 → random available
port = await server.start()
# port is printed on stdout so parent process can discover it
await server.publish("proxy.flow", flow_dict)
await server.stop()
```

### Client (TcpBridgeClient)

```python
def on_event(topic, data):
    hook_bus.publish("flow", Flow.from_dict(data))

client = TcpBridgeClient(host="127.0.0.1", port=port, on_event=on_event)
await client.start()  # retries connection with 1s backoff
# ...
await client.stop()
```

### Wire Protocol

Messages are newline-delimited JSON:
```
{"topic":"proxy.flow","data":{"id":"...","method":"GET","url":"...",...}}\n
```

The client sends a heartbeat newline periodically. The server keeps the connection open until an error occurs.
