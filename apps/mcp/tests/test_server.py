"""
Tests for pwnproxy-mcp server (API wrapper mode).

Tests MCPApiClient with mocked httpx, error handling, session headers,
and JSON-RPC fallback path.
"""

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_MCP_SRC = _REPO_ROOT / "apps/mcp/src"
for p in (_REPO_ROOT, _MCP_SRC):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

PYTHON = sys.executable
SERVER_MODULE = str(Path(__file__).resolve().parent.parent / "src")


def _server_script() -> str:
    return f"""
import sys
sys.path.insert(0, {SERVER_MODULE!r})
import builtins
_original_import = builtins.__import__
def _no_mcp(name, *args, **kwargs):
    if name == 'mcp' or name.startswith('mcp.'):
        raise ImportError(f'blocked: {{name}}')
    return _original_import(name, *args, **kwargs)
builtins.__import__ = _no_mcp
from pwnproxy_mcp.server import main
main()
"""


class TestMCPApiClient:
    @pytest.mark.asyncio
    async def test_get_success(self):
        from pwnproxy_mcp.server import MCPApiClient
        client = MCPApiClient(base_url="http://localhost:8000/api/v1")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json = MagicMock(return_value={"capture_enabled": True})
        client._client = AsyncMock()
        client._client.request = AsyncMock(return_value=mock_resp)
        result = await client.get("/proxy/status")
        assert result == {"capture_enabled": True}
        await client.close()

    @pytest.mark.asyncio
    async def test_post_success(self):
        from pwnproxy_mcp.server import MCPApiClient
        client = MCPApiClient(base_url="http://localhost:8000/api/v1")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json = MagicMock(return_value={"task_id": "abc123"})
        client._client = AsyncMock()
        client._client.request = AsyncMock(return_value=mock_resp)
        result = await client.post("/scan", params={"url": "http://target.com"})
        assert result == {"task_id": "abc123"}
        await client.close()

    @pytest.mark.asyncio
    async def test_delete_204(self):
        from pwnproxy_mcp.server import MCPApiClient
        client = MCPApiClient(base_url="http://localhost:8000/api/v1")
        mock_resp = MagicMock()
        mock_resp.status_code = 204
        client._client = AsyncMock()
        client._client.request = AsyncMock(return_value=mock_resp)
        result = await client.delete("/flows/1")
        assert result == {"ok": True}
        await client.close()

    @pytest.mark.asyncio
    async def test_error_404(self):
        from pwnproxy_mcp.server import MCPApiClient
        client = MCPApiClient(base_url="http://localhost:8000/api/v1")
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.json = MagicMock(return_value={"detail": "Not found"})
        mock_resp.text = "Not found"
        client._client = AsyncMock()
        client._client.request = AsyncMock(return_value=mock_resp)
        result = await client.get("/flows/999")
        assert result["error"] == "Not found"
        assert result["status_code"] == 404
        await client.close()

    @pytest.mark.asyncio
    async def test_connection_refused(self):
        import httpx
        from pwnproxy_mcp.server import MCPApiClient
        client = MCPApiClient(base_url="http://localhost:9999/api/v1")
        client._client = AsyncMock()
        client._client.request = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))
        result = await client.get("/health")
        assert result["status_code"] == 0
        assert "Connection refused" in result["error"]
        await client.close()

    @pytest.mark.asyncio
    async def test_timeout(self):
        import httpx
        from pwnproxy_mcp.server import MCPApiClient
        client = MCPApiClient(base_url="http://localhost:8000/api/v1")
        client._client = AsyncMock()
        client._client.request = AsyncMock(side_effect=httpx.TimeoutException("timed out"))
        result = await client.get("/health")
        assert result["status_code"] == 0
        assert "timed out" in result["error"]
        await client.close()

    @pytest.mark.asyncio
    async def test_configure(self):
        from pwnproxy_mcp.server import MCPApiClient
        client = MCPApiClient(base_url="http://localhost:8000/api/v1")
        assert str(client._client.base_url) == "http://localhost:8000/api/v1/"
        await client.close()

    @pytest.mark.asyncio
    async def test_proxy_toggle_no_body(self):
        from pwnproxy_mcp.server import MCPApiClient
        client = MCPApiClient(base_url="http://localhost:8000/api/v1")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json = MagicMock(return_value={"capture_enabled": False})
        client._client = AsyncMock()
        client._client.request = AsyncMock(return_value=mock_resp)
        result = await client.put("/proxy/toggle")
        assert result == {"capture_enabled": False}
        # Verify no json body was sent (proxy_toggle sends no payload)
        call_kwargs = client._client.request.call_args
        assert "json" not in call_kwargs.kwargs
        await client.close()

    @pytest.mark.asyncio
    async def test_repeater_send_raw_request(self):
        from pwnproxy_mcp.server import MCPApiClient
        client = MCPApiClient(base_url="http://localhost:8000/api/v1")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json = MagicMock(return_value={"task_id": "rpt-001"})
        client._client = AsyncMock()
        client._client.request = AsyncMock(return_value=mock_resp)
        raw = "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n"
        result = await client.post("/repeater/send", json={"raw_request": raw, "tab_id": 0})
        assert result == {"task_id": "rpt-001"}
        call_kwargs = client._client.request.call_args
        assert call_kwargs.kwargs["json"]["raw_request"] == raw
        await client.close()


class TestSessionHeader:
    def test_session_header_set(self):
        from pwnproxy_mcp.server import MCPApiClient
        client = MCPApiClient(base_url="http://localhost:8000/api/v1", session="pentest-01")
        assert client._client.headers.get("X-Pwnproxy-Session") == "pentest-01"

    def test_no_session_header(self):
        from pwnproxy_mcp.server import MCPApiClient
        client = MCPApiClient(base_url="http://localhost:8000/api/v1", session=None)
        assert "X-Pwnproxy-Session" not in client._client.headers


class TestAgentToken:
    """The MCP authenticates with the ``agent`` token; a 401 must explain itself."""

    @pytest.fixture(autouse=True)
    def isolated_config(self, tmp_path, monkeypatch):
        """Point the config dir at ``tmp_path`` and drop the env override."""
        monkeypatch.setenv("PWNPROXY_CONFIG_DIR", str(tmp_path))
        monkeypatch.delenv("PWNPROXY_API_TOKEN", raising=False)
        return tmp_path

    @pytest.mark.asyncio
    async def test_request_carries_the_bearer_from_mcp_token(self, isolated_config):
        import httpx
        from pwnproxy_mcp import server
        from pwnproxy_mcp.server import MCPApiClient

        (isolated_config / "mcp-token").write_text("agent-token-from-file", encoding="utf-8")
        client = MCPApiClient(base_url="http://localhost:8000/api/v1", session=None)
        seen: dict[str, str | None] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["authorization"] = request.headers.get("Authorization")
            return httpx.Response(200, json={"ok": True})

        # Swap only the transport: the default headers (the token) are applied by
        # the client when it builds the request — which is what this proves.
        client._client._transport = httpx.MockTransport(handler)
        assert await client.get("/whoami") == {"ok": True}
        assert seen["authorization"] == "Bearer agent-token-from-file"
        assert server.token_file() == isolated_config / "mcp-token"
        await client.close()

    def test_env_token_wins_over_the_file(self, isolated_config, monkeypatch):
        from pwnproxy_mcp.server import MCPApiClient

        (isolated_config / "mcp-token").write_text("agent-token-from-file", encoding="utf-8")
        monkeypatch.setenv("PWNPROXY_API_TOKEN", "env-token-for-ci")
        client = MCPApiClient(base_url="http://localhost:8000/api/v1", session=None)
        assert client._client.headers.get("Authorization") == "Bearer env-token-for-ci"

    def test_without_any_token_no_authorization_header(self, isolated_config):
        from pwnproxy_mcp.server import MCPApiClient

        client = MCPApiClient(base_url="http://localhost:8000/api/v1", session=None)
        assert "Authorization" not in client._client.headers

    def test_configure_preserves_the_token(self, isolated_config, monkeypatch):
        from pwnproxy_mcp import server

        (isolated_config / "mcp-token").write_text("agent-token-from-file", encoding="utf-8")
        monkeypatch.setattr(server, "_client", None)
        server._handle_configure({"api_base": "http://otro:17171/api/v1", "session": ""})
        client = server.get_client()
        assert str(client._client.base_url) == "http://otro:17171/api/v1/"
        assert client._client.headers.get("Authorization") == "Bearer agent-token-from-file"

    @pytest.mark.asyncio
    async def test_401_explains_the_file_and_the_command(self, isolated_config):
        from pwnproxy_mcp.server import MCPApiClient

        client = MCPApiClient(base_url="http://localhost:8000/api/v1", session=None)
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.json = MagicMock(return_value={"detail": "Missing or invalid API token"})
        mock_resp.text = "Missing or invalid API token"
        client._client = AsyncMock()
        client._client.request = AsyncMock(return_value=mock_resp)
        result = await client.get("/flows")
        assert result["status_code"] == 401
        assert str(isolated_config / "mcp-token") in result["error"]
        assert "pwnproxy api token --scope agent" in result["error"]
        assert "Connection refused" not in result["error"]
        await client.close()


class TestJsonRpcFallback:
    def test_list_tools(self):
        proc = subprocess.Popen(
            [PYTHON, "-c", _server_script()],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        msg = json.dumps({"jsonrpc": "2.0", "method": "list_tools", "params": {}, "id": 1})
        stdout, stderr = proc.communicate(input=msg + "\n", timeout=10)
        assert proc.returncode == 0, f"Server error: {stderr}"
        response = json.loads(stdout.strip())
        assert "result" in response
        tools = response["result"]["tools"]
        tool_names = [t["name"] for t in tools]
        assert "configure" in tool_names
        assert "proxy_status" in tool_names
        assert "list_flows" in tool_names
        assert "list_findings" in tool_names
        assert "trigger_scan" in tool_names
        assert "list_sessions" in tool_names
        assert "repeater_send" in tool_names
        assert "intruder_run" in tool_names
        assert "health_check" in tool_names

    def test_list_resources(self):
        proc = subprocess.Popen(
            [PYTHON, "-c", _server_script()],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        msg = json.dumps({"jsonrpc": "2.0", "method": "list_resources", "params": {}, "id": 2})
        stdout, stderr = proc.communicate(input=msg + "\n", timeout=10)
        assert proc.returncode == 0
        response = json.loads(stdout.strip())
        uris = [r["uriTemplate"] for r in response["result"]["resources"]]
        assert "flows://{flow_id}" in uris
        assert "findings://{scanner}/{finding_id}" in uris
        assert "sessions://{name}" in uris

    def test_call_tool_api_down(self):
        proc = subprocess.Popen(
            [PYTHON, "-c", _server_script()],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**__import__("os").environ, "PUBLIC_API_BASE": "http://127.0.0.1:19999/api/v1"},
        )
        msg = json.dumps({
            "jsonrpc": "2.0",
            "method": "call_tool",
            "params": {"name": "health_check", "arguments": {}},
            "id": 3,
        })
        stdout, stderr = proc.communicate(input=msg + "\n", timeout=10)
        assert proc.returncode == 0
        response = json.loads(stdout.strip())
        result = response["result"]
        assert "error" in result
        assert result["status_code"] == 0

    def test_full_session_sequence(self):
        """Full JSON-RPC session over stdio: initialize → ping → list_tools → list_resources.

        One subprocess, one response per request, ids echoed in order.
        """
        proc = subprocess.Popen(
            [PYTHON, "-c", _server_script()],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        lines = [
            json.dumps({"jsonrpc": "2.0", "method": "initialize", "params": {}, "id": 1}),
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}),
            json.dumps({"jsonrpc": "2.0", "method": "ping", "params": {}, "id": 2}),
            json.dumps({"jsonrpc": "2.0", "method": "list_tools", "params": {}, "id": 3}),
            json.dumps({"jsonrpc": "2.0", "method": "list_resources", "params": {}, "id": 4}),
        ]
        stdout, stderr = proc.communicate(input="\n".join(lines) + "\n", timeout=10)
        assert proc.returncode == 0, f"Server error: {stderr}"
        responses = [json.loads(r) for r in stdout.strip().splitlines()]
        # notifications/initialized is acked silently: 5 requests in, 4 responses out
        assert len(responses) == 4
        assert [r["id"] for r in responses] == [1, 2, 3, 4]

        init = responses[0]["result"]
        assert init["protocolVersion"] == "2024-11-05"
        assert responses[1]["result"] == "pong"

        tools = [t["name"] for t in responses[2]["result"]["tools"]]
        assert "get_flow" in tools
        assert "list_findings" in tools

        uris = [r["uriTemplate"] for r in responses[3]["result"]["resources"]]
        assert "flows://{flow_id}" in uris
        assert "sessions://{name}" in uris


# ---------------------------------------------------------------------------
# Plugin configuration: the generic tools, the agent token and the 403/422 text
# ---------------------------------------------------------------------------

#: Token written to the temporary config dir: the ``agent`` one the MCP uses.
AGENT_TOKEN = "agent-token-4c1d9f7a"

PLUGIN = "example-checker"
SETTINGS_PATH = f"/api/v1/plugins/{PLUGIN}/settings"
COLLECTION_PATH = f"/api/v1/plugins/{PLUGIN}/collections/webhooks"

#: The whole tool list, written by hand: the three places that declare tools
#: (``_register_tools``, ``TOOL_DEFINITIONS`` and the dispatch of the repl) have
#: to declare exactly this, and a new tool means editing this set on purpose.
EXPECTED_TOOLS = frozenset(
    {
        "configure",
        "proxy_status",
        "proxy_toggle",
        "list_flows",
        "get_flow",
        "delete_flow",
        "list_findings",
        "delete_finding",
        "list_sessions",
        "create_session",
        "switch_session",
        "get_scope",
        "update_scope",
        "repeater_send",
        "list_repeater_tabs",
        "intruder_run",
        "get_intruder_results",
        "list_tasks",
        "get_task",
        "cancel_task",
        "list_plugins",
        "toggle_plugin",
        "plugin_schema",
        "plugin_config_get",
        "plugin_config_set",
        "plugin_collection_list",
        "plugin_collection_create",
        "plugin_collection_update",
        "plugin_collection_delete",
        "plugin_action",
        "trigger_scan",
        "get_scan_results",
        "export_results",
        "health_check",
    }
)

#: The example plugin of the design, which is **not** in the catalog of this
#: machine. One literal is not a registry: the names that matter are taken
#: from :func:`catalog_plugin_names`, the single source of truth.
DESIGN_EXAMPLE = "example-checker"


def catalog_plugin_names() -> tuple[str, ...]:
    """Return every plugin name of the real catalog (plus the design's example).

    The spec's rule is "no tool contains the name of a catalog plugin", so the
    names come from the catalog itself — writing them here would be the parallel
    registry ``tests/architecture/test_scanner_registries.py`` forbids.
    """
    from pwnproxy.plugins.core.catalog import discover_plugins

    names = tuple(record.name for record in discover_plugins())
    return names + (DESIGN_EXAMPLE,)


class FakeApi:
    """An in-memory API behind ``httpx.MockTransport``.

    Records every request (method, full URL, decoded body, ``Authorization``) and
    answers from a route table keyed by ``(method, path)``; an unknown route
    answers ``200 {"ok": true}`` so the dispatch test does not need 30 entries.
    """

    def __init__(self) -> None:
        self.replies: dict[tuple[str, str], tuple[int, object]] = {}
        self.seen: list[dict[str, object]] = []

    def handler(self, request):
        body = json.loads(request.content) if request.content else None
        self.seen.append(
            {
                "method": request.method,
                "url": str(request.url),
                "body": body,
                "authorization": request.headers.get("Authorization"),
            }
        )
        status, reply = self.replies.get((request.method, request.url.path), (200, {"ok": True}))
        if status == 204:
            return httpx.Response(204, request=request)
        return httpx.Response(status, json=reply, request=request)


@pytest.fixture
def api(tmp_path, monkeypatch):
    """Install :class:`FakeApi` as the API the MCP talks to.

    The agent token goes to a **temporary** config dir, so the real
    ``~/.pwnproxy`` is never read and the ``PWNPROXY_API_TOKEN`` of the session
    (a ``full`` token) cannot mask what this package sends.
    """
    import httpx
    from pwnproxy_mcp import server

    monkeypatch.setenv("PWNPROXY_CONFIG_DIR", str(tmp_path))
    monkeypatch.delenv("PWNPROXY_API_TOKEN", raising=False)
    (tmp_path / "mcp-token").write_text(AGENT_TOKEN, encoding="utf-8")

    fake = FakeApi()
    client = server.MCPApiClient(base_url="http://api.test/api/v1", session=None)
    client._client._transport = httpx.MockTransport(fake.handler)
    monkeypatch.setattr(server, "_client", client)
    return fake


#: One call per generic tool: (tool, arguments, method, path, body sent).
GENERIC_TOOL_CALLS = [
    ("plugin_schema", {"name": PLUGIN}, "GET", f"/api/v1/plugins/{PLUGIN}/schema", None),
    ("plugin_config_get", {"name": PLUGIN}, "GET", SETTINGS_PATH, None),
    (
        "plugin_config_set",
        {"name": PLUGIN, "values": {"retries": 3}},
        "PATCH",
        SETTINGS_PATH,
        {"values": {"retries": 3}},
    ),
    (
        "plugin_collection_list",
        {"name": PLUGIN, "collection": "webhooks"},
        "GET",
        COLLECTION_PATH,
        None,
    ),
    (
        "plugin_collection_create",
        {"name": PLUGIN, "collection": "webhooks", "values": {"name": "app"}},
        "POST",
        COLLECTION_PATH,
        {"values": {"name": "app"}},
    ),
    (
        "plugin_collection_update",
        {
            "name": PLUGIN,
            "collection": "webhooks",
            "item_id": "app",
            "values": {"name": "app2"},
        },
        "PATCH",
        f"{COLLECTION_PATH}/app",
        {"values": {"name": "app2"}},
    ),
    (
        "plugin_collection_delete",
        {"name": PLUGIN, "collection": "webhooks", "item_id": "app"},
        "DELETE",
        f"{COLLECTION_PATH}/app",
        None,
    ),
    (
        "plugin_action",
        {"name": PLUGIN, "action": "ping", "parameters": {"name": "app"}},
        "POST",
        f"/api/v1/plugins/{PLUGIN}/actions/ping",
        {"parameters": {"name": "app"}},
    ),
]

#: Arguments that satisfy every declared tool (the dispatch test calls them all).
UNIVERSAL_ARGS = {
    "name": PLUGIN,
    "collection": "webhooks",
    "item_id": "app",
    "action": "ping",
    "values": {"name": "app"},
    "parameters": {"name": "app"},
    "flow_id": 1,
    "scanner": "sqli",
    "finding_id": "f-1",
    "attack_id": "a-1",
    "task_id": "t-1",
    "scan_id": "s-1",
    "url": "http://example.test/",
    "raw_request": "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
}


class TestPluginConfigTools:
    """Each generic tool hits its route of section A, with the ``agent`` token."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("tool,arguments,method,path,body", GENERIC_TOOL_CALLS)
    async def test_each_generic_tool_calls_its_route(self, api, tool, arguments, method, path, body):
        from pwnproxy_mcp.server import handle_call

        if method == "DELETE":
            api.replies[(method, path)] = (204, None)

        result = await handle_call(tool, arguments)

        assert result == {"ok": True}
        assert [(r["method"], r["url"], r["body"], r["authorization"]) for r in api.seen] == [
            (method, f"http://api.test{path}", body, f"Bearer {AGENT_TOKEN}")
        ]

    @pytest.mark.asyncio
    async def test_secret_write_403_keeps_the_server_message(self, api):
        """The tool decides nothing: the 403's ``detail`` is what the agent sees."""
        from pwnproxy_mcp.server import handle_call

        detail = (
            "Secret fields can only be written with a token of scope 'full' "
            "(Web UI or CLI)"
        )
        api.replies[("PATCH", SETTINGS_PATH)] = (403, {"detail": detail})

        result = await handle_call(
            "plugin_config_set", {"name": PLUGIN, "values": {"signing_key": "CANARIO-1111"}}
        )

        assert result == {"error": detail, "status_code": 403}
        assert len(api.seen) == 1
        assert "CANARIO-1111" not in json.dumps(result)

    @pytest.mark.asyncio
    async def test_validation_422_keeps_the_field_and_the_message(self, api):
        """The ``422`` body is ``{"field", "message"}``; it is passed through as JSON."""
        from pwnproxy_mcp.server import handle_call

        api.replies[("PATCH", SETTINGS_PATH)] = (
            422,
            {"detail": {"field": "retries", "message": "must be at most 5"}},
        )

        result = await handle_call(
            "plugin_config_set", {"name": PLUGIN, "values": {"retries": 9}}
        )

        assert result == {
            "error": '{"field": "retries", "message": "must be at most 5"}',
            "status_code": 422,
        }

    @pytest.mark.asyncio
    async def test_config_get_passes_the_set_shape_through(self, api):
        """A secret arrives as ``{"set": true}`` and the MCP asks for nothing else.

        One request: the package does not go looking for the value behind a
        ``{"set": …}`` — knowing what is secret is the server's job, so there is
        no second call for a leak to hide in.
        """
        from pwnproxy_mcp.server import handle_call

        body = {
            "plugin": PLUGIN,
            "schema_version": 1,
            "values": {"signing_key": {"set": True}, "environment": {"value": "lab"}},
        }
        api.replies[("GET", SETTINGS_PATH)] = (200, body)

        result = await handle_call("plugin_config_get", {"name": PLUGIN})

        assert (result, len(api.seen)) == (body, 1)

    @pytest.mark.asyncio
    async def test_toggle_plugin_sends_no_body_and_reports_the_server_state(self, api):
        """The route inverts the state and ignores the body, so no body is sent."""
        from pwnproxy_mcp.server import handle_call

        api.replies[("POST", "/api/v1/plugins/sqli/toggle")] = (
            200,
            {"status": "disabled", "name": "sqli"},
        )

        result = await handle_call("toggle_plugin", {"name": "sqli"})

        assert result == {"status": "disabled", "name": "sqli"}
        assert [(r["method"], r["url"], r["body"]) for r in api.seen] == [
            ("POST", "http://api.test/api/v1/plugins/sqli/toggle", None)
        ]

    def test_toggle_plugin_has_no_enabled_argument(self):
        """The lie of the old tool (``enabled=False`` switching a plugin on) is gone."""
        from pwnproxy_mcp.server import TOOL_DEFINITIONS

        definition = next(t for t in TOOL_DEFINITIONS if t["name"] == "toggle_plugin")

        assert definition["inputSchema"] == {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        }
        assert "flip" in definition["description"].lower()


class _ToolRecorder:
    """Minimal stand-in for ``FastMCP``: records the name of each declared tool."""

    def __init__(self) -> None:
        self.names: list[str] = []

    def tool(self):
        def register(fn):
            self.names.append(fn.__name__)
            return fn

        return register


class TestToolDeclarations:
    """A tool lives in three places at once; a mismatch is a tool that lies."""

    def test_the_three_sites_declare_the_same_tools(self, api):
        from pwnproxy_mcp import server

        recorder = _ToolRecorder()
        server._register_tools(recorder)

        assert set(recorder.names) == {t["name"] for t in server.TOOL_DEFINITIONS}
        assert set(recorder.names) == EXPECTED_TOOLS

    @pytest.mark.asyncio
    async def test_every_declared_tool_is_dispatched(self, api):
        """``handle_call`` answers for every declared tool (no "Unknown tool")."""
        from pwnproxy_mcp.server import handle_call

        # ``configure`` builds a new client by design
        # (``test_configure_preserves_the_token``), so it would leave this
        # test's MockTransport behind.
        names = sorted(EXPECTED_TOOLS - {"configure"})

        results = {name: await handle_call(name, dict(UNIVERSAL_ARGS)) for name in names}

        assert results == {name: {"ok": True} for name in names}
        assert len(api.seen) == len(names)

    @pytest.mark.asyncio
    async def test_an_unknown_tool_still_raises(self, api):
        from pwnproxy_mcp.server import handle_call

        with pytest.raises(ValueError, match="Unknown tool: plugin_magic"):
            await handle_call("plugin_magic", {})

    def test_no_tool_is_named_after_a_plugin(self):
        """The tools are generic: one set for every plugin, not one per plugin."""
        names = catalog_plugin_names()
        assert names[:1] != ()  # the catalog is readable (an empty tuple proves nothing)
        assert [
            tool
            for tool in sorted(EXPECTED_TOOLS)
            if any(plugin in tool for plugin in names)
        ] == []


#: What the plugin tools call, as section A declares it. A route that is renamed
#: or moved in the API fails here instead of at an agent's tool call.
TOOL_ROUTES = {
    "plugin_config": [
        ("GET", "/api/v1/plugins/{name}/schema"),
        ("GET", "/api/v1/plugins/{name}/settings"),
        ("PATCH", "/api/v1/plugins/{name}/settings"),
        ("GET", "/api/v1/plugins/{name}/collections/{collection}"),
        ("POST", "/api/v1/plugins/{name}/collections/{collection}"),
        ("PATCH", "/api/v1/plugins/{name}/collections/{collection}/{item_id}"),
        ("DELETE", "/api/v1/plugins/{name}/collections/{collection}/{item_id}"),
        ("POST", "/api/v1/plugins/{name}/actions/{action}"),
    ],
    "plugins": [("POST", "/api/v1/plugins/{name}/toggle")],
}


def test_every_route_a_tool_uses_exists_in_the_real_routers():
    """The paths of the tools are checked against the app, not against memory."""
    import importlib

    missing = []
    for module_name, expected in TOOL_ROUTES.items():
        router = importlib.import_module(f"pwnproxy.transport.rest.{module_name}").router
        declared = {
            (method, route.path) for route in router.routes for method in route.methods
        }
        missing += [row for row in expected if row not in declared]
    assert missing == []

