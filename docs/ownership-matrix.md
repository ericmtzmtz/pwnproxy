# Ownership Matrix

Every piece of mutable state in pwnproxy has exactly **one owner** who writes it.
Consumers read via snapshots or events — never by reaching into the owner's internals.

| State | Owner | Writers | Readers | Notes |
|---|---|---|---|---|
| **Scope** | SessionManager | SessionManager only | Crawler (snapshot + event), Proxy (snapshot), API (query) | `scope.updated` event notifies consumers; restart is fallback |
| **Jobs** | JobStorage | JobStorage (via `transition()`) | API (query), UI (WS events) | `JobState` enum; `transition()` is the single mutation point |
| **Findings** | FindingService | Scanners, Triage pipeline | API, Reports, UI | Findings are append-mostly; triage mutates severity |
| **Session** | SessionManager | SessionManager only | API (query), MCP, UI | Create/load/delete only through SessionManager |
| **Proxy config** | SessionManager | SessionManager only | ProxyProcess (snapshot) | Updated via `/sessions/proxy` endpoint |
| **Plugin config** | PluginLoader | API (toggle), SessionManager (load/save) | API (query), UI | Disabled list persisted per session |
| **Flows (traffic.db)** | StorageAddon | StorageAddon (mitmproxy response hook) | API, Reports, UI | Append-only; auto-scan publishes `done` event |

## Architecture Rule

A change that introduces a **new writer** to a state with an existing owner **SHALL** include justification in the PR:

1. Why the existing owner cannot handle the write
2. Why the new write cannot be routed through an event to the owner
3. Confirmation that this does not create a split-brain scenario

## Event Semantics

Events are **notifications**, not owners. Publishing `scope.updated` does not move
the authoritative copy of scope — it lives in `SessionManager.scope`. Consumers
who receive the event update their local cache; if they miss the event, they can
always re-fetch from the owner.
