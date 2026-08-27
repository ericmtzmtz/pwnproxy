# Burp Suite Migration

pwnproxy is not a Burp Suite clone — see the README's comparison table for the architectural differences. This page covers migrating *from* Burp and interoperating with it.

## Importing Scope

1. Export your Burp Suite configuration: **Burp → Settings → Project → Save copy of project file**
2. Or export scope JSON: **Settings → Project → Scope → Copy scope** → save as JSON
3. Import into pwnproxy:

```bash
pwnproxy import burp --config burp-config.json
```

The import extracts:

- **In-scope targets** → pwnproxy scope configuration
- **Excluded targets** → pwnproxy exclusion rules

Imported scope is written to the active session's scope and applied immediately (the crawler worker receives a live `scope.updated` event — no restart required).

## What's Not Imported

- BApp / BCheck rules (Java API lock-in, not supported)
- Session handling rules (pwnproxy handles sessions differently)
- Intruder attack definitions (manual replay in pwnproxy intruder)

## Chaining behind Burp

pwnproxy can sit downstream of Burp as an upstream proxy:

1. In Burp Suite, go to **Settings → Network → Connections → Upstream Proxy Servers**
2. Add a rule: Destination host `*`, Proxy host `127.0.0.1`, Port `8080`
3. Ensure Burp's own listener is on a different port (e.g., `:8081`)

## Workflow Comparison

| Task | Burp Suite | pwnproxy |
|------|-----------|----------|
| Proxy traffic | Proxy tab | TUI traffic view |
| Manual testing | Repeater | `pwnproxy repeater` |
| Fuzzing | Intruder | `pwnproxy intruder` |
| Scanning | Active/Passive scan | Automated + `pwnproxy scan` |
| Session tokens | Session handler | `pwnproxy session` |
| Plugins | BApp Store (Java) | `pwnproxy plugin install` (Python) |
| AI integration | N/A | `pwnproxy-mcp` MCP server |
| CI/CD | N/A | `pwnproxy scan --output sarif` |
