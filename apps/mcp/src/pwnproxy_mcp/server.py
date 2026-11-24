"""The pwnproxy MCP server: the agent's tools, backed by the local REST API.

The API requires ``Authorization: Bearer <token>`` on every route except
``/api/v1/health``. This package is standalone (its only requirements are ``mcp``
and ``httpx``, see ``pyproject.toml``), so it cannot import
``pwnproxy.shared.api_token``; it mirrors the two rules that matter:

* the token is the **agent** one — ``mcp-token`` in the pwnproxy config dir
  (``PWNPROXY_CONFIG_DIR`` or ``~/.pwnproxy``) — and ``PWNPROXY_API_TOKEN``, when
  defined, wins over the file (the CI path);
* a ``401`` is translated into a message that names the file and the command that
  shows the token, never into a bare "401" or a connection error.

The token is read when a client is built, so rotating it is followed by
``configure(api_base=...)`` (which rebuilds the client) or a restart.

A plugin publishes its own configuration (settings, collections, actions) and
this server exposes it through **generic** tools —one set for every plugin, no
tool per plugin—: ``plugin_schema``, ``plugin_config_get``, ``plugin_config_set``,
``plugin_collection_list``, ``plugin_collection_create``,
``plugin_collection_update``, ``plugin_collection_delete`` and ``plugin_action``.
These tools neither filter nor decide anything: they return the API's body as it
came, and an error keeps the server's ``detail`` verbatim. Because the token is
the ``agent`` one, the API answers ``403`` to a write that carries a ``secret``
field and to an action declared ``requires_scope: "full"`` — that is a scope
answer, not a business rule. Secrets are therefore never read or written from
here: ``GET`` renders them as ``{"set": true|false}`` and the ``403`` explains
where a human has to do it (the Web UI or the CLI).
"""

import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

# Default API location. This package is standalone (its only requirements are
# `mcp` and `httpx`), so it cannot import `pwnproxy.shared.ports`; keep these two
# numbers in sync with DEFAULT_API_PORT there. The guard
# `tests/architecture/test_ports.py` fails if the old ports come back.
DEFAULT_API_PORT = 17171
DEFAULT_API_BASE = f"http://127.0.0.1:{DEFAULT_API_PORT}/api/v1"

API_BASE = os.environ.get("PUBLIC_API_BASE", DEFAULT_API_BASE)
SESSION_NAME = os.environ.get("PWNPROXY_SESSION")
TIMEOUT = 30.0

#: File that holds the ``agent`` token (same name the server uses).
MCP_TOKEN_FILE = "mcp-token"

#: Environment variable that overrides the token from the file (CI).
TOKEN_ENV = "PWNPROXY_API_TOKEN"


def config_dir() -> Path:
    """Return the pwnproxy config dir: ``PWNPROXY_CONFIG_DIR`` or ``~/.pwnproxy``."""
    return Path(os.environ.get("PWNPROXY_CONFIG_DIR") or Path.home() / ".pwnproxy")


def token_file() -> Path:
    """Return the path of the agent token file (``<config_dir>/mcp-token``)."""
    return config_dir() / MCP_TOKEN_FILE


def read_agent_token() -> Optional[str]:
    """Return the agent token: the env value if set, else the file, else ``None``.

    Read on every call (not at import) so ``configure`` and the tests see the
    current environment, and so a rotated file is picked up by the next client.
    An unreadable file counts as "no token": the API then answers ``503``/``401``
    and :func:`unauthorized_message` explains what to do.
    """
    env_token = (os.environ.get(TOKEN_ENV) or "").strip()
    if env_token:
        return env_token
    try:
        return token_file().read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def auth_headers() -> dict[str, str]:
    """Return ``{"Authorization": "Bearer <agent token>"}``, or ``{}`` without one."""
    token = read_agent_token()
    return {"Authorization": f"Bearer {token}"} if token else {}


def unauthorized_message() -> str:
    """Return the explanation of a ``401``, naming the file and the command."""
    return (
        "401 Unauthorized — the API rejected the token. The MCP uses the agent token in "
        f"{token_file()}; run 'pwnproxy api token --scope agent' to see it (or set "
        f"{TOKEN_ENV} to reuse a known token)."
    )


class MCPApiClient:
    def __init__(self, base_url: str = API_BASE, session: Optional[str] = SESSION_NAME):
        headers = auth_headers()
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
            if resp.status_code == 401:
                return {"error": unauthorized_message(), "status_code": 401}
            if resp.status_code >= 400:
                try:
                    detail = resp.json().get("detail", resp.text)
                except Exception:
                    detail = resp.text
                # A `422` is `{"field", "message"}`: publish it as JSON instead of
                # a Python repr, so the agent reads the server's own words.
                if not isinstance(detail, str):
                    detail = json.dumps(detail, default=str)
                return {"error": detail, "status_code": resp.status_code}
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

    def patch(self, path: str, **kwargs):
        """``PATCH``: the partial write of the plugin-configuration contract.

        Settings and collection items are written with ``PATCH`` on purpose
        (design D5): the missing keys are left untouched, so a client never has
        to resend —and therefore never has to be able to read— a secret.
        """
        return self._request("PATCH", path, **kwargs)

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
            resp = httpx.get(f"{API_BASE}/sessions", headers=auth_headers(), timeout=5)
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

Default API: http://127.0.0.1:17171/api/v1 (env: PUBLIC_API_BASE).

Authentication: every request carries the agent token (env PWNPROXY_API_TOKEN,
else <config dir>/mcp-token). A 401 means the token is missing or was rotated —
ask the user to run `pwnproxy api token --scope agent`.

If health_check returns Connection refused, ask the user for their 
 pwnproxy API URL (e.g. http://192.168.1.93:17171/api/v1) and call 
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
    async def configure(api_base: str = DEFAULT_API_BASE, session: str = "") -> str:
        """Point the client at another API URL/session (the agent token is re-read)."""
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
    async def toggle_plugin(name: str) -> str:
        """Flip a plugin's activation (no body: the API inverts the current state).

        There is no ``enabled`` argument on purpose: the route ignores the body
        and inverts what the plugin has, so asking for "enabled=false" used to
        turn a disabled plugin **on**. Read the state from ``list_plugins`` after
        the call.
        """
        return _ok(await c.post(f"/plugins/{name}/toggle"))

    # -- Plugin configuration: one generic set of tools for every plugin ------
    # Nothing here knows a plugin by name: the shape comes from the plugin's own
    # schema. These tools never filter or decide; they return the API body and
    # its `detail` as they came. A 403 is a scope answer from the token (the
    # `agent` one cannot write a secret field nor run a `full` action), and
    # secrets are never read or written from here.

    @mcp.tool()
    async def plugin_schema(name: str) -> str:
        """Configuration a plugin declares: settings, collections and actions.

        Empty lists mean the plugin declares no configuration (still a 200). A
        403 means this resource is not covered by your token's scope.
        """
        return _ok(await c.get(f"/plugins/{name}/schema"))

    @mcp.tool()
    async def plugin_config_get(name: str) -> str:
        """Read a plugin's settings.

        A secret field comes back as {"set": true|false}, never as a value. A 403
        means this resource is not covered by your token's scope.
        """
        return _ok(await c.get(f"/plugins/{name}/settings"))

    @mcp.tool()
    async def plugin_config_set(name: str, values: dict) -> str:
        """Write some settings (partial: only the keys sent are written).

        A 403 means this resource is not covered by your token's scope: writing a
        secret field needs the `full` token (the Web UI or the CLI), so a secret
        cannot be written from here.
        """
        return _ok(await c.patch(f"/plugins/{name}/settings", json={"values": values}))

    @mcp.tool()
    async def plugin_collection_list(name: str, collection: str) -> str:
        """Read one of a plugin's collections (its items and its capacity).

        A 403 means this resource is not covered by your token's scope.
        """
        return _ok(await c.get(f"/plugins/{name}/collections/{collection}"))

    @mcp.tool()
    async def plugin_collection_create(name: str, collection: str, values: dict) -> str:
        """Create one item in a collection.

        `409` means the collection is full; `422` carries the plugin's own rule
        with its `field` and `message`. A `403` means this resource is not covered
        by your token's scope (a secret field needs the `full` token).
        """
        return _ok(
            await c.post(f"/plugins/{name}/collections/{collection}", json={"values": values})
        )

    @mcp.tool()
    async def plugin_collection_update(
        name: str, collection: str, item_id: str, values: dict
    ) -> str:
        """Change some fields of one item (partial: only the keys sent are written).

        A `403` means this resource is not covered by your token's scope (a secret
        field needs the `full` token); `404` means the item is gone.
        """
        return _ok(
            await c.patch(
                f"/plugins/{name}/collections/{collection}/{item_id}",
                json={"values": values},
            )
        )

    @mcp.tool()
    async def plugin_collection_delete(name: str, collection: str, item_id: str) -> str:
        """Delete one item of a collection (`404` when it is already gone).

        A 403 means this resource is not covered by your token's scope.
        """
        return _ok(await c.delete(f"/plugins/{name}/collections/{collection}/{item_id}"))

    @mcp.tool()
    async def plugin_action(name: str, action: str, parameters: dict) -> str:
        """Run an action a plugin declares.

        A short action answers `{"status": "completed", "result": …}`; a long one
        answers `{"status": "running", "task_id": …}` and its result lands in
        `get_task`. A 403 means this resource is not covered by your token's scope
        (an action that requires `full` cannot be run by the `agent` token), and a
        `409` means the plugin is not loaded.
        """
        return _ok(
            await c.post(f"/plugins/{name}/actions/{action}", json={"parameters": parameters})
        )

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
    {"name": "toggle_plugin", "description": "Flip a plugin's activation (the API inverts its state; no body)", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}},
    {"name": "plugin_schema", "description": "Configuration a plugin declares: settings, collections, actions. A 403 means the resource is outside your token's scope", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}},
    {"name": "plugin_config_get", "description": "Read a plugin's settings; secrets come back as {set: bool}, never as a value", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}},
    {"name": "plugin_config_set", "description": "Write some settings (partial). A secret field needs the full token, so a 403 is expected here", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}, "values": {"type": "object"}}, "required": ["name", "values"]}},
    {"name": "plugin_collection_list", "description": "Read one of a plugin's collections", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}, "collection": {"type": "string"}}, "required": ["name", "collection"]}},
    {"name": "plugin_collection_create", "description": "Create one item in a collection (409 = full, 422 = the plugin's rule)", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}, "collection": {"type": "string"}, "values": {"type": "object"}}, "required": ["name", "collection", "values"]}},
    {"name": "plugin_collection_update", "description": "Change some fields of one item (partial)", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}, "collection": {"type": "string"}, "item_id": {"type": "string"}, "values": {"type": "object"}}, "required": ["name", "collection", "item_id", "values"]}},
    {"name": "plugin_collection_delete", "description": "Delete one item of a collection", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}, "collection": {"type": "string"}, "item_id": {"type": "string"}}, "required": ["name", "collection", "item_id"]}},
    {"name": "plugin_action", "description": "Run a plugin action: inline result, or a task_id for a long one (403 = outside your token's scope)", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}, "action": {"type": "string"}, "parameters": {"type": "object"}}, "required": ["name", "action", "parameters"]}},
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
    api_base = arguments.get("api_base", DEFAULT_API_BASE)
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
        "toggle_plugin": lambda: c.post(f"/plugins/{arguments['name']}/toggle"),
        "plugin_schema": lambda: c.get(f"/plugins/{arguments['name']}/schema"),
        "plugin_config_get": lambda: c.get(f"/plugins/{arguments['name']}/settings"),
        "plugin_config_set": lambda: c.patch(f"/plugins/{arguments['name']}/settings", json={"values": arguments.get("values", {})}),
        "plugin_collection_list": lambda: c.get(f"/plugins/{arguments['name']}/collections/{arguments['collection']}"),
        "plugin_collection_create": lambda: c.post(f"/plugins/{arguments['name']}/collections/{arguments['collection']}", json={"values": arguments.get("values", {})}),
        "plugin_collection_update": lambda: c.patch(f"/plugins/{arguments['name']}/collections/{arguments['collection']}/{arguments['item_id']}", json={"values": arguments.get("values", {})}),
        "plugin_collection_delete": lambda: c.delete(f"/plugins/{arguments['name']}/collections/{arguments['collection']}/{arguments['item_id']}"),
        "plugin_action": lambda: c.post(f"/plugins/{arguments['name']}/actions/{arguments['action']}", json={"parameters": arguments.get("parameters", {})}),
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
