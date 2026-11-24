# MCP Server

## Overview

pwnproxy ships an MCP (Model Context Protocol) server that wraps the REST API.
Any MCP-compatible agent (Claude Desktop, Copilot, custom agents) can control
the proxy, read traffic/findings, manage sessions, run scans, and export reports
through this server.

The MCP server runs as a stdio subprocess. It connects to the pwnproxy REST API
via HTTP and exposes each API endpoint as an MCP tool.

## Authentication

The API now requires a token on every route except `GET /api/v1/health`, and the MCP uses the
`agent` token:

| Source | Scope | When |
|---|---|---|
| `PWNPROXY_API_TOKEN` | `full` | Set in the MCP `env` block: it wins over the file |
| `<config_dir>/mcp-token` | `agent` | The normal case |

`<config_dir>` is `PWNPROXY_CONFIG_DIR` when set, otherwise `~/.pwnproxy`. `pwnproxy start` creates
`mcp-token` on its first run; `pwnproxy api token --scope agent` prints it. The header goes on every
request (`Authorization: Bearer <token>`), and `configure(api_base=...)` keeps it: the client is
rebuilt and re-reads the token.

```bash
# The token the MCP uses
pwnproxy api token --scope agent
```

`GET /api/v1/health` needs no token, so `health_check` works even with a broken token.

### A `401` from a tool

A `401` comes back as an explicit error, never as a connection failure:

```
401 Unauthorized — the API rejected the token. The MCP uses the agent token in
/home/you/.pwnproxy/mcp-token; run 'pwnproxy api token --scope agent' to see it
(or set PWNPROXY_API_TOKEN to reuse a known token).
```

What to do, in order:

1. `pwnproxy api token --scope agent` — the file exists? If it does not, start the API once
   (`pwnproxy start`) or rotate that scope (`pwnproxy api token --rotate --scope agent`).
2. If the token was rotated, restart the MCP server (or call `configure(api_base=...)`) so the
   client re-reads the file. The MCP reads the token when it builds its HTTP client, not per call.
3. Check `whoami` to see which scope the token really has:
   `curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:17171/api/v1/auth/whoami`.

### The scope is not a sandbox

The credentials of your test accounts do not travel through the MCP tools: the routes that carry
them demand `full`, and the MCP holds an `agent` token. The `agent` scope keeps secrets out of the
MCP tools, but it does not contain an agent with a shell on the machine: such an agent can read
`~/.pwnproxy/api-token` and get `full`. To contain an agent, run it on another machine or under
another user.

## Quick Start

1. Start pwnproxy (API on default port 17171):
   ```bash
   pwnproxy start
   ```

2. Configure your AI agent to use the MCP server:
   ```json
   {
     "mcpServers": {
       "pwnproxy": {
         "command": "python",
         "args": ["-m", "apps.mcp.src.pwnproxy_mcp.server"]
       }
     }
   }
   ```

3. The agent auto-discovers all tools and their schemas.

## Installation

The MCP server lives at `apps/mcp/`. To use it on a new machine:

```bash
# Copy the folder
scp -r apps/mcp user@remote:~/.pwnproxy-mcp

# Install dependencies
cd ~/.pwnproxy-mcp
pip install httpx mcp

# Or install as a package (creates pwnproxy-mcp command)
pip install -e .

# Run
python -m pwnproxy_mcp.server
```

## Remote Setup

The MCP server can run on a different machine than pwnproxy. Copy the folder and
point your agent to it:

```bash
# Copy MCP server to remote machine
scp -r apps/mcp user@remote:~/.pwnproxy-mcp
```

Then configure your agent with the remote path:

```json
{
  "mcpServers": {
    "pwnproxy": {
      "command": "python",
      "args": ["-m", "pwnproxy_mcp.server"],
      "env": {
        "PUBLIC_API_BASE": "http://192.168.1.93:17171/api/v1",
        "PWNPROXY_SESSION": "default"
      }
    }
  }
}
```

The agent connects to the MCP server via stdio (SSH tunnel or local). The MCP
server connects to pwnproxy's API via HTTP — update `PUBLIC_API_BASE` to point
to your pwnproxy instance.

A remote MCP also needs the **token of the machine running the API**: copy its `mcp-token` into the
remote `<config_dir>`, point `PWNPROXY_CONFIG_DIR` at that directory, or set `PWNPROXY_API_TOKEN`
(the `full` token) in the `env` block. Without one every tool answers `401`.

### Using env vars (no configure tool needed)

Set `PUBLIC_API_BASE` and `PWNPROXY_SESSION` in the agent's MCP config `env`
block. The MCP server reads them at startup and skips needing a `configure()`
call:

```json
{
  "mcpServers": {
    "pwnproxy": {
      "command": "python",
      "args": ["-m", "pwnproxy_mcp.server"],
      "env": {
        "PUBLIC_API_BASE": "http://192.168.1.93:17171/api/v1",
        "PWNPROXY_SESSION": "my-session"
      }
    }
  }
}
```

## Docker (future)

A Docker image will be provided in future releases. For now:

```dockerfile
FROM python:3.14-slim
COPY apps/mcp /opt/pwnproxy-mcp
RUN pip install httpx mcp
CMD ["python", "-m", "pwnproxy_mcp.server"]
```

Build and run:
```bash
docker build -t pwnproxy-mcp .
docker run -e PUBLIC_API_BASE=http://host.docker.internal:17171/api/v1 pwnproxy-mcp
```

Note: The MCP protocol requires stdio transport. For Docker, use `-i` flag:
```bash
docker run -i -e PUBLIC_API_BASE=http://host.docker.internal:17171/api/v1 pwnproxy-mcp
```

## Agent Configuration

Add the JSON snippet above to your agent's MCP configuration file:

| Agent | Config File | Location |
|---|---|---|
| **OpenCode** | `opencode.jsonc` | `~/.config/opencode/opencode.jsonc` — add under `"mcpServers"` object |
| **Claude Desktop** | `claude_desktop_config.json` | macOS: `~/Library/Application Support/Claude/claude_desktop_config.json` |
| | | Windows: `%APPDATA%\Claude\claude_desktop_config.json` |
| **Cline / Roo** | `cline_mcp_settings.json` | `~/.config/cline/cline_mcp_settings.json` |
| **Windsurf** | `mcp_config.json` | `.windsurf/` in project root |
| **Continue (VS Code)** | `config.json` | `~/.continue/config.json` — add under `"experimental.mcpServers"` |

### OpenCode example

File `~/.config/opencode/opencode.jsonc`:
```jsonc
{
  "mcpServers": {
    "pwnproxy": {
      "command": "python",
      "args": ["-m", "apps.mcp.src.pwnproxy_mcp.server"]
    }
  }
}
```

### Claude Desktop example (Windows)

File `%APPDATA%\Claude\claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "pwnproxy": {
      "command": "python",
      "args": ["-m", "apps.mcp.src.pwnproxy_mcp.server"]
    }
  }
}
```

### Test the connection

```bash
# From the pwnproxy project root, run the MCP server directly:
python -m apps.mcp.src.pwnproxy_mcp.server

# It waits for JSON-RPC on stdin. Send a tools list request:
echo '{"method":"list_tools","id":1}' | python -m apps.mcp.src.pwnproxy_mcp.server
# Expected response lists all ~26 tools
```

## Custom Ports

If pwnproxy runs on non-default ports, call the `configure` tool first:

```
configure(api_base="http://localhost:5000/api/v1", session="my-session")
```

The default API URL is `http://127.0.0.1:17171/api/v1`.

## Available Tools

| Tool |
|------| 
| `configure` | Set custom API base URL and session |
| `proxy_status` | Get proxy capture status |
| `proxy_toggle` | Toggle capture on/off |
| `list_flows` | List proxied flows |
| `get_flow` | Get flow by ID |
| `delete_flow` | Delete a flow |
| `list_findings` | List scanner findings |
| `delete_finding` | Delete a finding |
| `list_sessions` | List all sessions |
| `create_session` | Create a new session |
| `switch_session` | Switch active session |
| `get_scope` | Get current scope config |
| `update_scope` | Update scope rules |
| `repeater_send` | Send raw HTTP request via repeater |
| `list_repeater_tabs` | List repeater tabs |
| `intruder_run` | Launch intruder attack |
| `get_intruder_results` | Get intruder results |
| `list_tasks` | List tasks (scan/intruder/repeater) |
| `get_task` | Get task details |
| `cancel_task` | Cancel a running task |
| `list_plugins` | List loaded plugins |
| `toggle_plugin` | Flip a plugin's activation (no body: the API inverts the state) |
| `plugin_schema` | Configuration a plugin declares (settings, collections, actions) |
| `plugin_config_get` | Read a plugin's settings (a secret as `set`/`unset`) |
| `plugin_config_set` | Write some settings (partial) |
| `plugin_collection_list` | Read one collection of a plugin |
| `plugin_collection_create` | Create one item in a collection |
| `plugin_collection_update` | Change some fields of one item (partial) |
| `plugin_collection_delete` | Delete one item |
| `plugin_action` | Run an action a plugin declares (inline or as a task) |
| `trigger_scan` | Trigger scan on a URL |
| `get_scan_results` | Get scan results |
| `export_results` | Export scan results (json/sarif/html/pdf) |
| `health_check` | Check API health |

### Plugin configuration tools

The eight `plugin_*` tools are **generic**: none of them knows a plugin by name. The shape of a
plugin's settings, its collections and its actions comes from its own schema, so the tools work for
any plugin — built in, installed, or one you write later — without an MCP release.

```
plugin_schema(name="example-checker")
plugin_config_set(name="example-checker", values={"environment": "staging"})
plugin_collection_create(name="example-checker", collection="webhooks",
                         values={"name": "ci", "url": "https://hooks.example.test/ci",
                                 "events": ["finding"]})
plugin_action(name="example-checker", action="send_test",
              parameters={"name": "app", "payload": "{\"event\": \"test\"}"})
get_task(task_id="<task_id>")   # a long action's result
```

- A `403` is a **scope** answer from the token, not a business permission: the MCP holds the `agent`
  token, so writing a declared secret field or running an action declared `requires_scope="full"`
  is refused before the plugin is asked. That is what keeps the credentials of your test accounts
  away from the model.
- **Secrets are never read or written from the MCP.** No tool returns a secret value: a secret
  setting comes back as `{"set": true|false}`, and there is no route behind these tools that would
  hand the value over. Writing one is the Web UI's or the CLI's job.
- `409` means "the plugin cannot be served now" (`plugin '<n>' is not loaded` for an action,
  `collection '<c>' is full`, an invalid schema); `422` carries the rule that was broken as
  `{"field", "message"}`; `404` means the plugin, the collection or the action is not declared.
- A write is partial on `plugin_config_set` and `plugin_collection_update`: only the keys you send
  are written, the rest keep their value.
- Configuration can be read and written with the plugin **disabled**; an action needs it loaded.

## Workflow Examples

### Scan a target and get findings

```
configure(api_base="http://localhost:17171/api/v1")
trigger_scan(url="http://bwapp.local/sqli_1.php?title=test")
get_task(task_id="<task_id_from_response>")
# repeat get_task until status="completed"
list_findings(scanner="sqli")
```

### Send a captured request to Repeater

```
repeater_send(
  raw_request="GET /api/users HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer token\r\n\r\n"
)
get_task(task_id="<task_id>")
```

### Set scope and scan

```
update_scope(in_scope=["*.target.com"], out_of_scope=["*.ads.target.com"], enabled=True)
trigger_scan(url="https://api.target.com/endpoint")
```

## Architecture

```
┌────────────────────────┐     stdio      ┌──────────────────────┐
│  AI Agent              │◄──────────────►│  MCP Server          │
│  (Claude / Copilot)    │  JSON-RPC      │  (pwnproxy MCP)      │
└────────────────────────┘                └──────────┬───────────┘
                                                     │ HTTP
                                                     ▼
                                           ┌──────────────────────┐
                                           │  pwnproxy REST API   │
                                           │  (FastAPI :17171)    │
                                           └──────────────────────┘
```

The MCP server is a thin translation layer. It does NOT contain business logic —
all operations delegate to the REST API.
