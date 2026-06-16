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
        mock_resp.json.return_value = {"capture_enabled": True}
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
        mock_resp.json.return_value = {"task_id": "abc123"}
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
        mock_resp.json.return_value = {"detail": "Not found"}
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
        tools = response["result"]
        tool_names = [t["name"] for t in tools]
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
        uris = [r["uriTemplate"] for r in response["result"]]
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
