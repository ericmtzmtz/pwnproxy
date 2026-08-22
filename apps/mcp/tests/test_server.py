"""
Tests for pwnproxy-mcp server (API wrapper mode).

Tests MCPApiClient with mocked httpx, error handling, session headers,
and JSON-RPC fallback path.
"""

import asyncio
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

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
        from pwnproxy_mcp.server import MCPApiClient
        import httpx
        client = MCPApiClient(base_url="http://localhost:9999/api/v1")
        client._client = AsyncMock()
        client._client.request = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))
        result = await client.get("/health")
        assert result["status_code"] == 0
        assert "Connection refused" in result["error"]
        await client.close()

    @pytest.mark.asyncio
    async def test_timeout(self):
        from pwnproxy_mcp.server import MCPApiClient
        import httpx
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
