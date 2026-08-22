import asyncio
import json
import logging
import os
import sys
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

API_BASE = os.environ.get("PUBLIC_API_BASE", "http://127.0.0.1:8000/api/v1")
SESSION_NAME = os.environ.get("PWNPROXY_SESSION")
TIMEOUT = 30.0


class MCPApiClient:
    def __init__(self, base_url: str = API_BASE, session: Optional[str] = SESSION_NAME):
        headers = {}
        if session:
            headers["X-Pwnproxy-Session"] = session
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers=headers,
            timeout=httpx.Timeout(TIMEOUT),
        )

    async def close(self):
        await self._client.aclose()

    async def _request(self, method: str, path: str, **kwargs) -> Any:
        try:
            resp = await self._client.request(method, path, **kwargs)
            if resp.status_code == 204:
                return {"ok": True}
            if resp.status_code >= 400:
                try:
                    detail = resp.json().get("detail", resp.text)
                except Exception:
                    detail = resp.text
                return {"error": str(detail), "status_code": resp.status_code}
            return resp.json()
        except httpx.ConnectError:
            return {"error": "Connection refused — is pwnproxy API running?", "status_code": 0}
        except httpx.TimeoutException:
            return {"error": f"Request timed out after {TIMEOUT}s", "status_code": 0}
        except Exception as e:
            return {"error": str(e), "status_code": 0}

    def get(self, path: str, **kwargs):
        return self._request("GET", path, **kwargs)

    def post(self, path: str, **kwargs):
        return self._request("POST", path, **kwargs)

    def put(self, path: str, **kwargs):
        return self._request("PUT", path, **kwargs)

    def delete(self, path: str, **kwargs):
        return self._request("DELETE", path, **kwargs)


_client: Optional[MCPApiClient] = None


def get_client() -> MCPApiClient:
    global _client
    if _client is None:
        _client = MCPApiClient()
    return _client


def _ok(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")

    if SESSION_NAME:
        try:
            resp = httpx.get(f"{API_BASE}/sessions", timeout=5)
            if resp.status_code == 200:
                names = [s["name"] for s in resp.json()]
                if SESSION_NAME not in names:
                    logger.error("Session '%s' not found. Available: %s", SESSION_NAME, ", ".join(names))
                    sys.exit(1)
            else:
                logger.warning("Could not verify session '%s': API unavailable", SESSION_NAME)
        except Exception as e:
            logger.warning("Could not verify session '%s': %s", SESSION_NAME, e)

    try:
        from mcp.server.fastmcp import FastMCP
        mcp = FastMCP("pwnproxy", instructions="""pwnproxy MCP server.

Default API: http://127.0.0.1:8000/api/v1 (env: PUBLIC_API_BASE).

If health_check returns Connection refused, ask the user for their 
 pwnproxy API URL (e.g. http://192.168.1.93:8000/api/v1) and call 
 configure(api_base=\"<url>\") to set it before retrying.
""")
        _register_tools(mcp)
        _register_resources(mcp)
        mcp.run(transport="stdio")
    except ImportError:
        logger.warning("mcp SDK not installed, falling back to JSON-RPC stdio")
        _stdio_repl()


def _register_tools(mcp):
    c = get_client()

    @mcp.tool()
    async def configure(api_base: str = "http://127.0.0.1:8000/api/v1", session: str = "") -> str:
        global _client
        _client = MCPApiClient(base_url=api_base, session=session or None)
        return _ok({"status": "configured", "api_base": api_base})

    @mcp.tool()
    async def proxy_status() -> str:
        return _ok(await c.get("/proxy/status"))

    @mcp.tool()
    async def proxy_toggle() -> str:
        return _ok(await c.put("/proxy/toggle"))

    @mcp.tool()
    async def list_flows(limit: int = 50, offset: int = 0) -> str:
        return _ok(await c.get("/flows", params={"limit": limit, "offset": offset}))

    @mcp.tool()
    async def get_flow(flow_id: int) -> str:
        return _ok(await c.get(f"/flows/{flow_id}"))

    @mcp.tool()
    async def delete_flow(flow_id: int) -> str:
        return _ok(await c.delete(f"/flows/{flow_id}"))

    @mcp.tool()
    async def list_findings(scanner: str = "", severity: str = "", limit: int = 50, offset: int = 0) -> str:
        if scanner:
            return _ok(await c.get(f"/findings/{scanner}", params={"severity": severity, "limit": limit, "offset": offset}))
        return _ok(await c.get("/findings", params={"severity": severity, "limit": limit, "offset": offset}))

    @mcp.tool()
    async def delete_finding(scanner: str, finding_id: str) -> str:
        return _ok(await c.delete(f"/findings/{scanner}/{finding_id}"))

    @mcp.tool()
    async def list_sessions() -> str:
        return _ok(await c.get("/sessions"))

    @mcp.tool()
    async def create_session(name: str) -> str:
        return _ok(await c.post("/sessions/manage", json={"action": "create", "name": name}))

    @mcp.tool()
    async def switch_session(name: str) -> str:
        return _ok(await c.post("/sessions/manage", json={"action": "load", "name": name}))

    @mcp.tool()
    async def get_scope() -> str:
        return _ok(await c.get("/sessions/scope"))

    @mcp.tool()
    async def update_scope(in_scope: list[str] = [], out_of_scope: list[str] = [], enabled: bool = True) -> str:
        return _ok(await c.put("/sessions/scope", json={"in_scope": in_scope, "out_of_scope": out_of_scope, "enabled": enabled}))

    @mcp.tool()
    async def repeater_send(raw_request: str, tab_id: int = 0) -> str:
        return _ok(await c.post("/repeater/send", json={"raw_request": raw_request, "tab_id": tab_id}))

    @mcp.tool()
    async def list_repeater_tabs() -> str:
        return _ok(await c.get("/repeater/tabs"))

    @mcp.tool()
    async def intruder_run(url: str, payload_positions: list[str] = [], wordlist: list[str] = [], mode: str = "sniper", concurrency: int = 5) -> str:
        return _ok(await c.post("/intruder/run", json={"url": url, "payload_positions": payload_positions, "wordlist": wordlist, "mode": mode, "concurrency": concurrency}))

    @mcp.tool()
    async def get_intruder_results(attack_id: str) -> str:
        return _ok(await c.get(f"/intruder/attack/{attack_id}"))

    @mcp.tool()
    async def list_tasks(type: str = "") -> str:
        params = {"type": type} if type else {}
        return _ok(await c.get("/tasks", params=params))

    @mcp.tool()
    async def get_task(task_id: str) -> str:
        return _ok(await c.get(f"/tasks/{task_id}"))

    @mcp.tool()
    async def cancel_task(task_id: str) -> str:
        return _ok(await c.post(f"/tasks/{task_id}/cancel"))

    @mcp.tool()
    async def list_plugins() -> str:
        return _ok(await c.get("/plugins"))

    @mcp.tool()
    async def toggle_plugin(name: str, enabled: bool) -> str:
        return _ok(await c.post(f"/plugins/{name}/toggle", json={"enabled": enabled}))

    @mcp.tool()
    async def trigger_scan(url: str, scanners: str = "", detection_depth: str = "fast", evasion_level: str = "none") -> str:
        params = {"url": url}
        if scanners:
            params["scanners"] = scanners
        if detection_depth:
            params["detection_depth"] = detection_depth
        if evasion_level:
            params["evasion_level"] = evasion_level
        return _ok(await c.post("/scan", params=params))

    @mcp.tool()
    async def get_scan_results(scan_id: str) -> str:
        return _ok(await c.get(f"/scan/{scan_id}"))

    @mcp.tool()
    async def export_results(scan_id: str, format: str = "json") -> str:
        return _ok(await c.get(f"/export/{scan_id}", params={"format": format}))

    @mcp.tool()
    async def health_check() -> str:
        return _ok(await c.get("/health"))


def _register_resources(mcp):
    c = get_client()

    @mcp.resource("flows://{flow_id}")
    async def flow_resource(flow_id: str) -> str:
        return _ok(await c.get(f"/flows/{flow_id}"))

    @mcp.resource("findings://{scanner}/{finding_id}")
    async def finding_resource(scanner: str, finding_id: str) -> str:
        return _ok(await c.get(f"/findings/{scanner}/{finding_id}"))

    @mcp.resource("sessions://{name}")
    async def session_resource(name: str) -> str:
        result = await c.get("/sessions")
        if isinstance(result, list):
            for s in result:
                if s.get("name") == name:
                    return _ok(s)
            return _ok({"error": f"Session '{name}' not found"})
        return _ok(result)


TOOL_DEFINITIONS = [
    {"name": "configure", "description": "Configure MCP client API base and session", "inputSchema": {"type": "object", "properties": {"api_base": {"type": "string"}, "session": {"type": "string"}}}},
    {"name": "proxy_status", "description": "Get proxy capture status", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "proxy_toggle", "description": "Toggle proxy capture on/off", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "list_flows", "description": "List proxied flows from DB", "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer"}, "offset": {"type": "integer"}}}},
    {"name": "get_flow", "description": "Get flow by ID", "inputSchema": {"type": "object", "properties": {"flow_id": {"type": "integer"}}, "required": ["flow_id"]}},
    {"name": "delete_flow", "description": "Delete a flow", "inputSchema": {"type": "object", "properties": {"flow_id": {"type": "integer"}}, "required": ["flow_id"]}},
    {"name": "list_findings", "description": "List scanner findings from DB", "inputSchema": {"type": "object", "properties": {"scanner": {"type": "string"}, "severity": {"type": "string"}, "limit": {"type": "integer"}, "offset": {"type": "integer"}}}},
    {"name": "delete_finding", "description": "Delete a finding", "inputSchema": {"type": "object", "properties": {"scanner": {"type": "string"}, "finding_id": {"type": "string"}}, "required": ["scanner", "finding_id"]}},
    {"name": "list_sessions", "description": "List all sessions", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "create_session", "description": "Create a new session", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}},
    {"name": "switch_session", "description": "Switch to a different session", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}},
    {"name": "get_scope", "description": "Get current scope config", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "update_scope", "description": "Update scope rules", "inputSchema": {"type": "object", "properties": {"in_scope": {"type": "array", "items": {"type": "string"}}, "out_of_scope": {"type": "array", "items": {"type": "string"}}, "enabled": {"type": "boolean"}}}},
    {"name": "repeater_send", "description": "Send raw HTTP request via repeater", "inputSchema": {"type": "object", "properties": {"raw_request": {"type": "string"}, "tab_id": {"type": "integer"}}, "required": ["raw_request"]}},
    {"name": "list_repeater_tabs", "description": "List repeater tabs", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "intruder_run", "description": "Launch intruder attack", "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}, "payload_positions": {"type": "array", "items": {"type": "string"}}, "wordlist": {"type": "array", "items": {"type": "string"}}, "mode": {"type": "string"}, "concurrency": {"type": "integer"}}, "required": ["url"]}},
    {"name": "get_intruder_results", "description": "Get intruder attack results", "inputSchema": {"type": "object", "properties": {"attack_id": {"type": "string"}}, "required": ["attack_id"]}},
    {"name": "list_tasks", "description": "List tasks (scan/intruder/repeater)", "inputSchema": {"type": "object", "properties": {"type": {"type": "string"}}}},
    {"name": "get_task", "description": "Get task status and result", "inputSchema": {"type": "object", "properties": {"task_id": {"type": "string"}}, "required": ["task_id"]}},
    {"name": "cancel_task", "description": "Cancel a running task", "inputSchema": {"type": "object", "properties": {"task_id": {"type": "string"}}, "required": ["task_id"]}},
    {"name": "list_plugins", "description": "List loaded plugins", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "toggle_plugin", "description": "Enable/disable a plugin", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}, "enabled": {"type": "boolean"}}, "required": ["name", "enabled"]}},
    {"name": "trigger_scan", "description": "Trigger scan on URL with detection depth and evasion level", "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}, "scanners": {"type": "string"}, "detection_depth": {"type": "string"}, "evasion_level": {"type": "string"}}, "required": ["url"]}},
    {"name": "get_scan_results", "description": "Get scan task results", "inputSchema": {"type": "object", "properties": {"scan_id": {"type": "string"}}, "required": ["scan_id"]}},
    {"name": "export_results", "description": "Export scan results (json/sarif/html/pdf)", "inputSchema": {"type": "object", "properties": {"scan_id": {"type": "string"}, "format": {"type": "string"}}, "required": ["scan_id"]}},
    {"name": "health_check", "description": "Check pwnproxy API health", "inputSchema": {"type": "object", "properties": {}}},
]

RESOURCE_DEFINITIONS = [
    {"name": "flows://{flow_id}", "description": "Flow details by ID", "uriTemplate": "flows://{flow_id}"},
    {"name": "findings://{scanner}/{finding_id}", "description": "Finding by scanner and ID", "uriTemplate": "findings://{scanner}/{finding_id}"},
    {"name": "sessions://{name}", "description": "Session info by name", "uriTemplate": "sessions://{name}"},
]


def _handle_configure(arguments: dict) -> dict:
    global _client
    api_base = arguments.get("api_base", "http://127.0.0.1:8000/api/v1")
    session = arguments.get("session", "") or None
    _client = MCPApiClient(base_url=api_base, session=session)
    return {"status": "configured", "api_base": api_base}


async def handle_call(tool_name: str, arguments: dict) -> Any:
    c = get_client()
    mapping = {
        "configure": lambda: _handle_configure(arguments),
        "proxy_status": lambda: c.get("/proxy/status"),
        "proxy_toggle": lambda: c.put("/proxy/toggle"),
        "list_flows": lambda: c.get("/flows", params={"limit": arguments.get("limit", 50), "offset": arguments.get("offset", 0)}),
        "get_flow": lambda: c.get(f"/flows/{arguments['flow_id']}"),
        "delete_flow": lambda: c.delete(f"/flows/{arguments['flow_id']}"),
        "list_findings": lambda: c.get(f"/findings/{arguments.get('scanner', '')}", params={"severity": arguments.get("severity", ""), "limit": arguments.get("limit", 50), "offset": arguments.get("offset", 0)}) if arguments.get("scanner") else c.get("/findings", params={"severity": arguments.get("severity", ""), "limit": arguments.get("limit", 50), "offset": arguments.get("offset", 0)}),
        "delete_finding": lambda: c.delete(f"/findings/{arguments['scanner']}/{arguments['finding_id']}"),
        "list_sessions": lambda: c.get("/sessions"),
        "create_session": lambda: c.post("/sessions/manage", json={"action": "create", "name": arguments["name"]}),
        "switch_session": lambda: c.post("/sessions/manage", json={"action": "load", "name": arguments["name"]}),
        "get_scope": lambda: c.get("/sessions/scope"),
        "update_scope": lambda: c.put("/sessions/scope", json={"in_scope": arguments.get("in_scope", []), "out_of_scope": arguments.get("out_of_scope", []), "enabled": arguments.get("enabled", True)}),
        "repeater_send": lambda: c.post("/repeater/send", json={"raw_request": arguments["raw_request"], "tab_id": arguments.get("tab_id", 0)}),
        "list_repeater_tabs": lambda: c.get("/repeater/tabs"),
        "intruder_run": lambda: c.post("/intruder/run", json={"url": arguments["url"], "payload_positions": arguments.get("payload_positions", []), "wordlist": arguments.get("wordlist", []), "mode": arguments.get("mode", "sniper"), "concurrency": arguments.get("concurrency", 5)}),
        "get_intruder_results": lambda: c.get(f"/intruder/attack/{arguments['attack_id']}"),
        "list_tasks": lambda: c.get("/tasks", params={"type": arguments["type"]} if arguments.get("type") else {}),
        "get_task": lambda: c.get(f"/tasks/{arguments['task_id']}"),
        "cancel_task": lambda: c.post(f"/tasks/{arguments['task_id']}/cancel"),
        "list_plugins": lambda: c.get("/plugins"),
        "toggle_plugin": lambda: c.post(f"/plugins/{arguments['name']}/toggle", json={"enabled": arguments["enabled"]}),
        "trigger_scan": lambda: c.post("/scan", params={"url": arguments["url"], **({"scanners": arguments["scanners"]} if arguments.get("scanners") else {}), **({"detection_depth": arguments["detection_depth"]} if arguments.get("detection_depth") else {}), **({"evasion_level": arguments["evasion_level"]} if arguments.get("evasion_level") else {})}),
        "get_scan_results": lambda: c.get(f"/scan/{arguments['scan_id']}"),
        "export_results": lambda: c.get(f"/export/{arguments['scan_id']}", params={"format": arguments.get("format", "json")}),
        "health_check": lambda: c.get("/health"),
    }
    handler = mapping.get(tool_name)
    if handler is None:
        raise ValueError(f"Unknown tool: {tool_name}")
    return await handler()


def _stdio_repl():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
            method = msg.get("method", "")
            params = msg.get("params", {})

            if method == "initialize":
                response = {
                    "jsonrpc": "2.0",
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}, "resources": {}},
                        "serverInfo": {"name": "pwnproxy", "version": "1.0.0"},
                    },
                    "id": msg.get("id"),
                }
            elif method == "notifications/initialized":
                continue
            elif method == "ping":
                response = {"jsonrpc": "2.0", "result": "pong", "id": msg.get("id")}
            elif method == "list_tools":
                response = {"jsonrpc": "2.0", "result": {"tools": TOOL_DEFINITIONS}, "id": msg.get("id")}
            elif method == "list_resources":
                response = {"jsonrpc": "2.0", "result": {"resources": RESOURCE_DEFINITIONS}, "id": msg.get("id")}
            elif method == "call_tool":
                result = loop.run_until_complete(handle_call(params.get("name", ""), params.get("arguments", {})))
                response = {"jsonrpc": "2.0", "result": result, "id": msg.get("id")}
            elif method == "read_resource":
                uri = params.get("uri", "")
                c = get_client()
                if uri.startswith("flows://"):
                    flow_id = uri[len("flows://"):]
                    result = loop.run_until_complete(c.get(f"/flows/{flow_id}"))
                elif uri.startswith("findings://"):
                    parts = uri[len("findings://"):].split("/")
                    if len(parts) == 2:
                        result = loop.run_until_complete(c.get(f"/findings/{parts[0]}/{parts[1]}"))
                    else:
                        result = {"error": f"Invalid findings URI: {uri}"}
                elif uri.startswith("sessions://"):
                    name = uri[len("sessions://"):]
                    sessions = loop.run_until_complete(c.get("/sessions"))
                    if isinstance(sessions, list):
                        result = next((s for s in sessions if s.get("name") == name), {"error": f"Session '{name}' not found"})
                    else:
                        result = sessions
                else:
                    response = {"jsonrpc": "2.0", "error": {"code": -32601, "message": f"Unknown resource: {uri}"}, "id": msg.get("id")}
                    print(json.dumps(response), flush=True)
                    continue
                response = {"jsonrpc": "2.0", "result": result, "id": msg.get("id")}
            else:
                response = {"jsonrpc": "2.0", "error": {"code": -32601, "message": f"Method not found: {method}"}, "id": msg.get("id")}

            print(json.dumps(response), flush=True)
        except Exception as e:
            error_response = {"jsonrpc": "2.0", "error": {"code": -32603, "message": str(e)}, "id": None}
            print(json.dumps(error_response), flush=True)

    loop.close()


if __name__ == "__main__":
    main()
