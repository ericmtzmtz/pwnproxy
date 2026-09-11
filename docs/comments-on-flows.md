# Comments on Flows

Per-flow annotations for the proxy view. Persisted in the per-session `traffic.db`, exposed via REST, fanned to the existing `traffic:{session}` room, and rendered in the Web UI.

## Why

Flows capture requests, but without notes the operator's hypotheses and work state live only in their head ("reflects `q` — try contextual XSS", "302 to admin — don't fuzz", "sets the admin JWT", "reviewed/exploited/FP"). Comments make the proxy a prioritized worklist and complete the first half of "real-time collaboration" (annotations).

## Model

Table `flow_comments` in `traffic.db` (co-located with `flows`):

```
id            INTEGER PK
flow_id       INTEGER indexed (flows.id, no enforced FK)
body          TEXT NOT NULL
kind          TEXT default 'note'   — note | flag | todo
resolved      BOOLEAN default false
author        TEXT nullable         — free-text (default local)
created_at    DATETIME UTC
updated_at    DATETIME UTC (on update)
```

`kind` + `resolved` avoid a plain-textarea graveyard; `author` is nullable for single-user local-first and ready for multi-user later. Additive migrations follow the `FindingStorage` pattern.

## REST API

All under `/api/v1/flows/{flow_id}/comments` (nested under the flow, so session scope is implicit via the per-session DB):

| Method | Path | Notes |
|---|---|---|
| `GET` | `/flows/{flow_id}/comments` | list ordered by id; 404 if flow missing |
| `POST` | `/flows/{flow_id}/comments` | body required, kind/resolved/author optional; 201; 404 if flow missing; 422 on bad kind |
| `PATCH` | `/flows/{flow_id}/comments/{comment_id}` | partial update; sets `updated_at`; 404 if not found or flow mismatch |
| `DELETE` | `/flows/{flow_id}/comments/{comment_id}` | 204; also cascades on `DELETE /flows/{id}` and `DELETE /flows` |

`GET /flows` and `GET /flows/{flow_id}` include an additive `comment_count` (scalar subquery) so the row can badge without N+1. `FlowOut` allows extra fields, so this is non-breaking.

## Bus & Rooms

On create/update/delete the handler publishes `comment.created` / `comment.updated` / `comment.deleted` on the HookBus with `{session_id, flow_id, comment_id, ...}`. `RoomDispatcher` subscribes to those channels ( `_CHANNELS` + `_ROOM_PREFIX → traffic` ) and fans to `traffic:{session_id}` — the same room the proxy already uses for flows. Untagged events are dropped (`_untagged` counter). No new room scheme. The Web UI re-fetches on mutation; a WS listener can also live-update via the room.

## Web UI

- `FlowDetail` gains a `Comments` panel below the request/response grid: list (kind badge, resolved state, timestamp, body, Resolve/Unresolve, Delete) + composer (kind select, text input, Add). Enter submits.
- `FlowRow` and `FlowDetail` show a `comment_count` badge (💬) when `flow.comment_count > 0`.
- New API client: `apps/web/src/api/comments/{calls,types}.ts`.

## Out of scope (v1)

Threads/replies, mentions/`finding_id` coupling, real auth, TUI flow detail, rich markdown, attachments, `pinned`.

## Files

- `pwnproxy/shared/db.py` — `FlowCommentORM`
- `pwnproxy/shared/comments/storage.py` — `FlowCommentStorage`
- `pwnproxy/transport/rest/traffic.py` — CRUD + `comment_count`
- `pwnproxy/transport/ws/events.py` — `comment.*` channels
- `apps/web/src/components/proxy/FlowDetail.tsx`, `FlowRow.tsx`
- Tests: `tests/core/test_comments_storage.py`, `tests/api/test_comments.py`
