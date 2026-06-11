"""
pwnproxy-mcp-enterprise — MCP server with HTTP transport, prompts, and audit logging.

Usage:
    pwnproxy-mcp-enterprise [--host 0.0.0.0] [--port 8100]

Requires: pip install pwnproxy-mcp[enterprise]
(Adds: uvicorn, fastapi, httpx)
"""

import json
import logging
import sys
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    print("pwnproxy-mcp[enterprise] requires mcp SDK: pip install mcp", file=sys.stderr)
    sys.exit(1)

from pwnproxy_mcp.server import _server


def main():
    import argparse
    parser = argparse.ArgumentParser(description="pwnproxy MCP Enterprise Server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address")
    parser.add_argument("--port", type=int, default=8100, help="HTTP port")
    parser.add_argument("--transport", choices=["sse", "stdio"], default="sse", help="Transport (default: SSE for HTTP)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")

    mcp = FastMCP(
        "pwnproxy-enterprise",
        instructions="""pwnproxy MCP Enterprise Server — AI agent integration for security testing.

Features beyond community edition:
• HTTP/SSE transport for remote agents
• Prompt templates for common security tasks
• Audit logging of all scan operations

Available tools:
- scan_url: Scan a target URL for vulnerabilities
- get_flow: Retrieve a scanned flow by ID
- list_flows: List all flows in the current session
- list_findings: List available scanners
- get_status: Get server and scanner health
""",
    )

    @mcp.tool()
    async def scan_url(url: str, scanners: str = "", timeout: int = 60) -> str:
        logger.info("Enterprise scan: url=%s scanners=%s timeout=%d", url, scanners, timeout)
        results = await _server.handle_scan_url(url, scanners, timeout)
        return json.dumps(results, indent=2, default=str)

    @mcp.tool()
    async def get_flow(flow_id: str) -> str:
        result = await _server.handle_get_flow(flow_id)
        if result is None:
            return json.dumps({"error": f"Flow '{flow_id}' not found"})
        return json.dumps(result, indent=2, default=str)

    @mcp.tool()
    async def list_flows() -> str:
        results = await _server.handle_list_flows()
        return json.dumps(results, indent=2, default=str)

    @mcp.tool()
    async def list_findings() -> str:
        results = await _server.handle_list_findings()
        return json.dumps(results, indent=2, default=str)

    @mcp.tool()
    async def get_status() -> str:
        results = await _server.handle_get_status()
        return json.dumps(results, indent=2, default=str)

    @mcp.resource("flows://{id}")
    async def flow_resource(id: str) -> str:
        result = await _server.handle_get_flow(id)
        if result is None:
            return json.dumps({"error": f"Flow '{id}' not found"})
        return json.dumps(result, indent=2, default=str)

    @mcp.resource("findings://{flow_id}")
    async def findings_resource(flow_id: str) -> str:
        findings = _server._findings_by_flow.get(flow_id, [])
        return json.dumps(findings, indent=2, default=str)

    @mcp.prompt()
    async def scan_and_review(url: str) -> str:
        return f"""Run a security scan on {url} and review the findings:

1. Call scan_url with url="{url}"
2. If findings exist, call get_status to see scanner health
3. Summarize each finding with: severity, type, parameter, and evidence
4. Provide remediation recommendations for each confirmed finding"""

    @mcp.prompt()
    async def analyze_flow(flow_id: str) -> str:
        return f"""Analyze the HTTP flow {flow_id}:

1. Retrieve it via the flows://{flow_id} resource
2. Check for findings via findings://{flow_id}
3. Evaluate: request method, URL, status code, response headers
4. Identify any security-relevant observations"""

    if args.transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run(transport="sse", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
