import asyncio
import builtins
import json
import logging
import sys
import uuid
from pathlib import Path
from typing import Any, Optional

import httpx

from pwnproxy.core.models import Flow
from pwnproxy.plugin.base import Finding
from pwnproxy.plugin.loader import PluginLoader

logger = logging.getLogger(__name__)


async def _build_loader() -> PluginLoader:
    from pwnproxy.scanners.sqli.plugin import SQLiScannerPlugin
    from pwnproxy.scanners.xss.plugin import XSSScannerPlugin
    from pwnproxy.scanners.lfi.plugin import LFIScannerPlugin
    from pwnproxy.scanners.xxe.plugin import XXEScannerPlugin
    from pwnproxy.scanners.ssrf.plugin import SSRFScannerPlugin

    from pwnproxy.scanners.sqli.scanner import SQLiScanner
    from pwnproxy.scanners.xss.scanner import XSSScanner
    from pwnproxy.scanners.lfi.scanner import LFIScanner
    from pwnproxy.scanners.xxe.scanner import XXEScanner
    from pwnproxy.scanners.ssrf.scanner import SSRFScanner
    from pwnproxy.scanners.sqli.storage import FindingStorage as SqliStorage
    from pwnproxy.scanners.xss.storage import XssFindingStorage as XssStorage
    from pwnproxy.scanners.lfi.storage import LfiFindingStorage as LfiStorage
    from pwnproxy.scanners.xxe.storage import XxeFindingStorage as XxeStorage
    from pwnproxy.scanners.ssrf.storage import SsrfFindingStorage as SsrfStorage

    import tempfile
    tmp = tempfile.mkdtemp(prefix="pwnproxy_mcp_")
    db_path = str(Path(tmp) / "results.db")

    sqli = SQLiScanner(None, storage=SqliStorage(db_path))
    xss = XSSScanner(None, storage=XssStorage(db_path))
    lfi = LFIScanner(None, storage=LfiStorage(db_path))
    xxe = XXEScanner(None, storage=XxeStorage(db_path))
    ssrf = SSRFScanner(None, storage=SsrfStorage(db_path))

    await sqli._storage.create_tables()
    await xss._storage.create_tables()
    await lfi._storage.create_tables()
    await xxe._storage.create_tables()
    await ssrf._storage.create_tables()

    loader = PluginLoader()

    await loader.load_builtin(SQLiScannerPlugin(sqli))
    await loader.load_builtin(XSSScannerPlugin(xss))
    await loader.load_builtin(LFIScannerPlugin(lfi))
    await loader.load_builtin(XXEScannerPlugin(xxe))
    await loader.load_builtin(SSRFScannerPlugin(ssrf))

    return loader


class PwnProxyMCPServer:
    def __init__(self, loader: PluginLoader):
        self._loader = loader
        self._flows: dict[str, dict] = {}
        self._findings_by_flow: dict[str, list[dict]] = {}

    async def handle_scan_url(self, url: str, scanners: str = "", timeout: int = 60) -> list[dict]:
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout), follow_redirects=True) as client:
            resp = await client.get(url)

        parsed = httpx.URL(url)
        flow = Flow(
            id=str(uuid.uuid4()),
            method="GET",
            url=url,
            request_headers={"host": parsed.host or ""},
            request_body=None,
            status_code=resp.status_code,
            response_headers=dict(resp.headers),
            response_body=resp.content,
            tls=url.startswith("https"),
        )

        flow_dict = _flow_to_dict(flow)
        self._flows[flow.id] = flow_dict

        findings = await self._loader.run_scan(flow)
        finding_dicts = [_finding_to_dict(f) for f in findings]
        self._findings_by_flow[flow.id] = finding_dicts
        return finding_dicts

    async def handle_get_flow(self, flow_id: str) -> Optional[dict]:
        return self._flows.get(flow_id)

    async def handle_list_flows(self) -> list[dict]:
        return builtins.list(self._flows.values())

    async def handle_list_findings(self) -> list[dict]:
        active = self._loader.list_active()
        return [p for p in active if p.get("category") == "scanner"]

    async def handle_get_status(self) -> dict:
        active = self._loader.list_active()
        stats = self._loader.watchdog_stats()
        return {
            "plugins": active,
            "watchdog": stats,
        }


def _flow_to_dict(f: Flow) -> dict:
    return {
        "id": f.id,
        "method": f.method,
        "url": f.url,
        "status_code": f.status_code,
        "request_headers": dict(f.request_headers),
        "response_headers": dict(f.response_headers) if f.response_headers else None,
        "duration_ms": f.duration_ms,
        "tls": f.tls,
        "error": f.error,
    }


def _finding_to_dict(f: Finding) -> dict:
    return {
        "scanner": f.scanner,
        "url": f.url,
        "method": f.method,
        "param_name": f.param_name,
        "param_location": f.param_location,
        "technique": f.technique,
        "severity": f.severity,
        "confidence": f.confidence,
        "payload": f.payload,
        "evidence": f.evidence,
        "timestamp": f.timestamp,
    }


_server: Optional[PwnProxyMCPServer] = None


async def _ensure_initialized() -> PwnProxyMCPServer:
    global _server
    if _server is None:
        loader = await _build_loader()
        _server = PwnProxyMCPServer(loader)
    return _server


async def handle_call(tool_name: str, arguments: dict) -> Any:
    srv = await _ensure_initialized()
    if tool_name == "scan_url":
        return await srv.handle_scan_url(
            url=arguments["url"],
            scanners=arguments.get("scanners", ""),
            timeout=arguments.get("timeout", 60),
        )
    elif tool_name == "get_flow":
        return await srv.handle_get_flow(flow_id=arguments["flow_id"])
    elif tool_name == "list_flows":
        return await srv.handle_list_flows()
    elif tool_name == "list_findings":
        return await srv.handle_list_findings()
    elif tool_name == "get_status":
        return await srv.handle_get_status()
    else:
        raise ValueError(f"Unknown tool: {tool_name}")


TOOL_DEFINITIONS = [
    {
        "name": "scan_url",
        "description": "Scan a target URL for vulnerabilities",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL to scan"},
                "scanners": {"type": "string", "description": "Comma-separated scanner names"},
                "timeout": {"type": "number", "description": "Scan timeout in seconds"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "get_flow",
        "description": "Retrieve a proxied flow by ID (from a previous scan_url call)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "flow_id": {"type": "string", "description": "Flow UUID to retrieve"},
            },
            "required": ["flow_id"],
        },
    },
    {
        "name": "list_flows",
        "description": "List all scanned flows in this session",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "list_findings",
        "description": "List available scanners and their status",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "get_status",
        "description": "Get proxy and scanner status",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
]

RESOURCE_DEFINITIONS = [
    {
        "name": "flows://{id}",
        "description": "Flow details by ID",
        "uriTemplate": "flows://{id}",
    },
    {
        "name": "findings://{flow_id}",
        "description": "Findings for a specific flow",
        "uriTemplate": "findings://{flow_id}",
    },
]


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")

    import os
    session = os.environ.get("PWNPROXY_SESSION")
    if session:
        import httpx
        api_base = os.environ.get("PUBLIC_API_BASE", "http://127.0.0.1:8000/api/v1")
        try:
            resp = httpx.get(f"{api_base}/sessions", timeout=5)
            if resp.status_code == 200:
                names = [s["name"] for s in resp.json()]
                if session not in names:
                    logger.error("Session '%s' not found. Available: %s", session, ", ".join(names))
                    sys.exit(1)
            else:
                logger.warning("Could not verify session '%s': API unavailable", session)
        except Exception as e:
            logger.warning("Could not verify session '%s': %s", session, e)

    srv = asyncio.run(_ensure_initialized())

    try:
        from mcp.server.fastmcp import FastMCP
        mcp = FastMCP("pwnproxy", instructions="pwnproxy MCP server for security scanning")

        @mcp.tool()
        async def scan_url(url: str, scanners: str = "", timeout: int = 60) -> str:
            results = await srv.handle_scan_url(url, scanners, timeout)
            return json.dumps(results, indent=2, default=str)

        @mcp.tool()
        async def get_flow(flow_id: str) -> str:
            result = await srv.handle_get_flow(flow_id)
            if result is None:
                return json.dumps({"error": f"Flow '{flow_id}' not found"})
            return json.dumps(result, indent=2, default=str)

        @mcp.tool()
        async def list_flows() -> str:
            results = await srv.handle_list_flows()
            return json.dumps(results, indent=2, default=str)

        @mcp.tool()
        async def list_findings() -> str:
            results = await srv.handle_list_findings()
            return json.dumps(results, indent=2, default=str)

        @mcp.tool()
        async def get_status() -> str:
            results = await srv.handle_get_status()
            return json.dumps(results, indent=2, default=str)

        @mcp.resource("flows://{id}")
        async def flow_resource(id: str) -> str:
            result = await srv.handle_get_flow(id)
            if result is None:
                return json.dumps({"error": f"Flow '{id}' not found"})
            return json.dumps(result, indent=2, default=str)

        @mcp.resource("findings://{flow_id}")
        async def findings_resource(flow_id: str) -> str:
            findings = srv._findings_by_flow.get(flow_id, [])
            return json.dumps(findings, indent=2, default=str)

        mcp.run(transport="stdio")
    except ImportError:
        logger.warning("mcp SDK not installed, falling back to JSON-RPC stdio")
        _stdio_repl()


def _stdio_repl():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    srv = loop.run_until_complete(_ensure_initialized())

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
            method = msg.get("method", "")
            params = msg.get("params", {})

            if method == "list_tools":
                response = {"jsonrpc": "2.0", "result": TOOL_DEFINITIONS, "id": msg.get("id")}
            elif method == "list_resources":
                response = {"jsonrpc": "2.0", "result": RESOURCE_DEFINITIONS, "id": msg.get("id")}
            elif method == "call_tool":
                result = loop.run_until_complete(handle_call(params.get("name", ""), params.get("arguments", {})))
                response = {"jsonrpc": "2.0", "result": result, "id": msg.get("id")}
            elif method == "read_resource":
                uri = params.get("uri", "")
                if uri.startswith("flows://"):
                    flow_id = uri[len("flows://"):]
                    result = loop.run_until_complete(srv.handle_get_flow(flow_id))
                elif uri.startswith("findings://"):
                    flow_id = uri[len("findings://"):]
                    result = srv._findings_by_flow.get(flow_id, [])
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
