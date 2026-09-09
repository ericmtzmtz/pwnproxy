# WebSocket Rooms

Scope: `specs/websocket-rooms/spec.md` (contract). This doc is the single reference for room usage.

## Room ID Scheme

One socket per room, path-based:

- `session:{session_name}` — scope, proxy status for that session
- `traffic:{session_name}` — flows (`response` / `flow_stored`) for that session
- `findings:{session_name}` — findings and `triage.updated` for that session
- `job:{job_id}` — `scan.*` / `crawl.*` / `bruteforce.*` progress for that job (job_id is opaque; may also carry `session_id`)

`session_name` is exactly `SessionManager.active_name` (`~/.pwnproxy/sessions/<name>/`). No UUIDs.

## Envelope

Room broadcasts use:

```json
{ "type": "<channel>", "session_id": "<name>", "job_id": "<id|optional>", "data": { ... } }
```

For `Flow` objects, `data` is `Flow.to_dict()` including `session_id` when set. Global streams (`/ws/traffic`, `/ws/findings`, `/ws/events`) keep flat payloads with `session_id` as an additive field (backward compatible).

Untagged events (no `session_id` and no `job_id`) are NOT fanned out to session/job rooms — logged and counted via `RoomDispatcher._untagged`.

## Endpoint

```
GET /ws/rooms/{room_id}
```

Consumes the room's queue via `RoomManager.broadcast`. The dispatcher (started once at app lifespan, reusing HookBus QoS/fan-out) fans global events into rooms.

## Auth / Close Codes

| Condition | Code | Meaning |
|-----------|------|---------|
| Unknown scheme or malformed `room_id` (no `:` or prefix not in `session,traffic,findings,job` or empty id) | 4404 | Invalid room |
| `session:{id}`, `traffic:{id}`, `findings:{id}` where `id` not in `SessionManager.list()` | 4403 | No such session |
| `job:{id}` | — | MAY skip session check (secret job_id, single-tenant) or require job belongs to known session |

`/ws/traffic`, `/ws/findings`, `/ws/events` remain global and unchanged (additive `session_id` only).

## Out of Scope v1

- Multi-join per socket (`{"action":"join"}`)
- Presence
- History replay on connect
