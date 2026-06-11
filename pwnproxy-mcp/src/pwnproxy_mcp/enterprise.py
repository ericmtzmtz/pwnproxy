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

logger = logging.getLogger(__name__)

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    print("pwnproxy-mcp[enterprise] requires mcp SDK: pip install mcp", file=sys.stderr)
    sys.exit(1)

from pwnproxy_mcp.server import get_client, _ok, _register_tools, _register_resources


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
- HTTP/SSE transport for remote agents
- Prompt templates for common security tasks
- Audit logging of all scan operations

Available tools:
- proxy_status / proxy_toggle: Control proxy capture
- list_flows / get_flow / delete_flow: Manage traffic
- list_findings / delete_finding: Manage findings
- list_sessions / create_session / switch_session: Session management
- get_scope / update_scope: Scope configuration
- repeater_send / list_repeater_tabs: Repeater operations
- intruder_run / get_intruder_results: Intruder attacks
- list_tasks / get_task / cancel_task: Task management
- list_plugins / toggle_plugin: Plugin management
- trigger_scan / get_scan_results: Scanning
- export_results: Export in JSON/SARIF/HTML/PDF
- health_check: API health
""",
    )

    _register_tools(mcp)
    _register_resources(mcp)

    c = get_client()

    @mcp.prompt()
    async def scan_and_review(url: str) -> str:
        return f"""Run a security scan on {url} and review the findings:

1. Call trigger_scan with url="{url}" (optional: detection_depth="deep" for thorough scan)
2. Poll get_scan_results until status is "completed"
3. Call list_findings to get all findings
4. Summarize each finding with: severity, type, parameter, and evidence
5. Provide remediation recommendations for each confirmed finding"""

    @mcp.prompt()
    async def analyze_flow(flow_id: str) -> str:
        return f"""Analyze the HTTP flow {flow_id}:

1. Retrieve it via the flows://{flow_id} resource
2. Evaluate: request method, URL, status code, response headers
3. Identify any security-relevant observations
4. Check for sensitive data exposure in response"""

    @mcp.prompt()
    async def full_engagement(target: str) -> str:
        return f"""Perform a full security engagement on {target}:

1. Call create_session to create a new session for this engagement
2. Call update_scope to set {target} as in-scope
3. Call proxy_toggle to enable capture
4. Call trigger_scan to scan the target
5. Call list_findings to review all findings
6. Call export_results to generate a report
7. Summarize findings and provide risk assessment"""

    if args.transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run(transport="sse", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
