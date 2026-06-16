# MCP Server

## Overview

pwnproxy ships an MCP (Model Context Protocol) server that wraps the REST API.
Any MCP-compatible agent (Claude Desktop, Copilot, custom agents) can control
the proxy, read traffic/findings, manage sessions, run scans, and export reports
through this server.

The MCP server runs as a stdio subprocess. It connects to the pwnproxy REST API
via HTTP and exposes each API endpoint as an MCP tool.

## Quick Start

1. Start pwnproxy (API on default port 8000):
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
        "PUBLIC_API_BASE": "http://192.168.1.93:8000/api/v1",
        "PWNPROXY_SESSION": "default"
      }
    }
  }
}
```

The agent connects to the MCP server via stdio (SSH tunnel or local). The MCP
server connects to pwnproxy's API via HTTP — update `PUBLIC_API_BASE` to point
to your pwnproxy instance.

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
        "PUBLIC_API_BASE": "http://192.168.1.93:8000/api/v1",
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
docker run -e PUBLIC_API_BASE=http://host.docker.internal:8000/api/v1 pwnproxy-mcp
```

Note: The MCP protocol requires stdio transport. For Docker, use `-i` flag:
```bash
docker run -i -e PUBLIC_API_BASE=http://host.docker.internal:8000/api/v1 pwnproxy-mcp
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

The default API URL is `http://127.0.0.1:8000/api/v1`.

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
| `toggle_plugin` | Enable/disable a plugin |
| `trigger_scan` | Trigger scan on a URL |
| `get_scan_results` | Get scan results |
| `export_results` | Export scan results (json/sarif/html/pdf) |
| `health_check` | Check API health |

## Workflow Examples

### Scan a target and get findings

```
configure(api_base="http://localhost:8000/api/v1")
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
                                           │  (FastAPI :8000)     │
                                           └──────────────────────┘
```

The MCP server is a thin translation layer. It does NOT contain business logic —
all operations delegate to the REST API.
