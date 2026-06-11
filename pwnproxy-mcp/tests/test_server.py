"""
Integration test for pwnproxy-mcp server.

Launches the MCP server as a subprocess via stdio, sends JSON-RPC messages,
and verifies responses. Tests both the FastMCP path and the JSON-RPC fallback.
"""

import asyncio
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

# Ensure both pwnproxy and pwnproxy_mcp are importable
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_MCP_SRC = _REPO_ROOT / "pwnproxy-mcp" / "src"
for p in (_REPO_ROOT, _MCP_SRC):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import pytest

SERVER_MODULE = str(Path(__file__).resolve().parent.parent / "src")
PYTHON = sys.executable


def _server_script(transport: str = "stdio") -> str:
    return f"""
import asyncio, json, sys
sys.path.insert(0, {SERVER_MODULE!r})

# Force JSON-RPC fallback by hiding mcp SDK
import builtins
_original_import = builtins.__import__

def _no_mcp(name, *args, **kwargs):
    if name == 'mcp' or name.startswith('mcp.'):
        raise ImportError(f'intentionally blocked: {{name}}')
    return _original_import(name, *args, **kwargs)

builtins.__import__ = _no_mcp

from pwnproxy_mcp.server import main
main()
"""


@pytest.fixture
def server_script_stdio():
    return _server_script("stdio")


def test_scan_url_tool(server_script_stdio):
    proc = subprocess.Popen(
        [PYTHON, "-c", server_script_stdio],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    request = json.dumps({
        "jsonrpc": "2.0",
        "method": "call_tool",
        "params": {"name": "list_tools", "arguments": {}},
        "id": 1,
    })
    stdout, stderr = proc.communicate(input=request, timeout=10)
    assert proc.returncode == 0, f"Server failed: {stderr}"
    assert stdout.strip(), "No output from server"


def test_json_rpc_list_tools(server_script_stdio):
    proc = subprocess.Popen(
        [PYTHON, "-c", server_script_stdio],
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
    assert isinstance(tools, list)
    tool_names = [t["name"] for t in tools]
    assert "scan_url" in tool_names
    assert "get_flow" in tool_names
    assert "list_flows" in tool_names
    assert "list_findings" in tool_names
    assert "get_status" in tool_names


def test_json_rpc_list_resources(server_script_stdio):
    proc = subprocess.Popen(
        [PYTHON, "-c", server_script_stdio],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    msg = json.dumps({"jsonrpc": "2.0", "method": "list_resources", "params": {}, "id": 2})
    stdout, stderr = proc.communicate(input=msg + "\n", timeout=10)

    assert proc.returncode == 0
    response = json.loads(stdout.strip())
    assert "result" in response
    uris = [r["uriTemplate"] for r in response["result"]]
    assert "flows://{id}" in uris
    assert "findings://{flow_id}" in uris


@pytest.mark.asyncio
async def test_get_status_tool():
    from pwnproxy_mcp.server import _ensure_initialized, _server
    srv = await _ensure_initialized()
    status = await srv.handle_get_status()
    assert "plugins" in status
    assert "watchdog" in status
    assert len(status["plugins"]) == 5


@pytest.mark.asyncio
async def test_get_flow_not_found():
    from pwnproxy_mcp.server import _ensure_initialized
    srv = await _ensure_initialized()
    result = await srv.handle_get_flow("nonexistent-id")
    assert result is None


@pytest.mark.asyncio
async def test_list_flows_empty():
    from pwnproxy_mcp.server import _ensure_initialized
    srv = await _ensure_initialized()
    flows = await srv.handle_list_flows()
    assert isinstance(flows, list)


@pytest.mark.asyncio
async def test_scan_url_httpbin():
    from pwnproxy_mcp.server import _ensure_initialized
    srv = await _ensure_initialized()
    findings = await srv.handle_scan_url("https://httpbin.org/get")
    assert isinstance(findings, list)
    flows = await srv.handle_list_flows()
    assert len(flows) >= 1
    assert flows[-1]["url"] == "https://httpbin.org/get"


@pytest.mark.asyncio
async def test_get_flow_after_scan():
    from pwnproxy_mcp.server import _ensure_initialized
    srv = await _ensure_initialized()
    await srv.handle_scan_url("https://httpbin.org/headers")
    flows = await srv.handle_list_flows()
    assert len(flows) >= 1
    flow = next(f for f in flows if f["url"] == "https://httpbin.org/headers")
    detail = await srv.handle_get_flow(flow["id"])
    assert detail is not None
    assert detail["url"] == "https://httpbin.org/headers"


@pytest.mark.asyncio
async def test_read_flow_resource():
    from pwnproxy_mcp.server import _ensure_initialized
    srv = await _ensure_initialized()
    await srv.handle_scan_url("https://httpbin.org/ip")
    flows = await srv.handle_list_flows()
    flow = next(f for f in flows if f["url"] == "https://httpbin.org/ip")
    resource = srv._flows.get(flow["id"])
    assert resource is not None
    assert resource["method"] == "GET"


@pytest.mark.asyncio
async def test_read_findings_resource():
    from pwnproxy_mcp.server import _ensure_initialized
    srv = await _ensure_initialized()
    await srv.handle_scan_url("https://httpbin.org/uuid")
    flows = await srv.handle_list_flows()
    flow = next(f for f in flows if f["url"] == "https://httpbin.org/uuid")
    findings = srv._findings_by_flow.get(flow["id"], [])
    assert isinstance(findings, list)
