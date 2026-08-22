"""
Unit tests for MCP server resource reading (read_resource dispatch).

Drives ``_stdio_repl()`` in-process with scripted JSON-RPC lines on a
fake stdin and captures responses from a fake stdout, monkeypatching
``get_client()`` to return a stub API client.
"""

import io
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_MCP_SRC = _REPO_ROOT / "apps/mcp/src"
for p in (_REPO_ROOT, _MCP_SRC):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from pwnproxy_mcp import server


class _ScriptedStdin(io.StringIO):
    """io.StringIO subclass that yields one line per iteration."""

    def __iter__(self):
        for line in self.getvalue().splitlines(keepends=True):
            yield line


class _StubClient:
    """Fake MCPApiClient: routes .get() by URL to canned responses."""

    def __init__(self):
        self._flows = AsyncMock(return_value={"id": 42, "url": "http://x/", "method": "GET"})
        self._finding = AsyncMock(return_value={"scanner": "sqli", "id": 7})
        self._sessions = AsyncMock(return_value=[{"name": "pentest-01"}, {"name": "other"}])
        self._client = None  # satisfy any attribute sniffing

    def get(self, path, *args, **kwargs):
        if path.startswith("/flows/"):
            return self._flows(path, *args, **kwargs)
        if path.startswith("/findings/"):
            return self._finding(path, *args, **kwargs)
        if path == "/sessions":
            return self._sessions(path, *args, **kwargs)
        return AsyncMock(return_value={"error": f"no stub for {path}"})()


def _run_repl(lines: list[str], client: _StubClient) -> list[dict]:
    stdin = _ScriptedStdin("".join(lines))
    stdout = io.StringIO()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(server, "get_client", lambda: client)
        # Route the repl's stdin/stdout through our fakes.
        import sys

        mp.setattr(sys, "stdin", stdin)
        mp.setattr(sys, "stdout", stdout)
        server._stdio_repl()

    responses = []
    for raw in stdout.getvalue().splitlines():
        if raw.strip():
            responses.append(json.loads(raw))
    return responses


class TestReadResource:
    def test_flows_uri_valid(self):
        client = _StubClient()
        responses = _run_repl(
            [
                json.dumps({"jsonrpc": "2.0", "method": "read_resource", "params": {"uri": "flows://42"}, "id": 10}) + "\n",
            ],
            client,
        )
        assert len(responses) == 1
        assert responses[0]["id"] == 10
        assert responses[0]["result"]["id"] == 42

    def test_findings_uri_valid(self):
        client = _StubClient()
        responses = _run_repl(
            [
                json.dumps({"jsonrpc": "2.0", "method": "read_resource", "params": {"uri": "findings://sqli/7"}, "id": 11}) + "\n",
            ],
            client,
        )
        assert len(responses) == 1
        assert responses[0]["id"] == 11
        assert responses[0]["result"]["scanner"] == "sqli"

    def test_findings_uri_malformed(self):
        client = _StubClient()
        responses = _run_repl(
            [
                json.dumps({"jsonrpc": "2.0", "method": "read_resource", "params": {"uri": "findings://only-one-part"}, "id": 12}) + "\n",
            ],
            client,
        )
        assert len(responses) == 1
        result = responses[0]["result"]
        assert "error" in result
        assert "Invalid findings URI" in result["error"]

    def test_sessions_uri_found(self):
        client = _StubClient()
        responses = _run_repl(
            [
                json.dumps({"jsonrpc": "2.0", "method": "read_resource", "params": {"uri": "sessions://pentest-01"}, "id": 13}) + "\n",
            ],
            client,
        )
        assert len(responses) == 1
        assert responses[0]["result"]["name"] == "pentest-01"

    def test_sessions_uri_not_found(self):
        client = _StubClient()
        responses = _run_repl(
            [
                json.dumps({"jsonrpc": "2.0", "method": "read_resource", "params": {"uri": "sessions://ghost"}, "id": 14}) + "\n",
            ],
            client,
        )
        assert len(responses) == 1
        result = responses[0]["result"]
        assert "error" in result
        assert "not found" in result["error"]

    def test_unknown_resource_uri(self):
        client = _StubClient()
        responses = _run_repl(
            [
                json.dumps({"jsonrpc": "2.0", "method": "read_resource", "params": {"uri": "bogus://x"}, "id": 15}) + "\n",
            ],
            client,
        )
        assert len(responses) == 1
        assert responses[0]["error"]["code"] == -32601
