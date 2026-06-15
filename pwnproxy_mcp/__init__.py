"""
pwnproxy-mcp MCP server package.

This package provides the MCP server functionality for pwnproxy.
"""

import importlib.util
import sys
from pathlib import Path

# Import from the actual package location
server_path = Path(__file__).parent.parent / "apps" / "mcp" / "src" / "pwnproxy_mcp" / "server.py"
spec = importlib.util.spec_from_file_location("pwnproxy_mcp.server", server_path)
server_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server_module)

# Export the symbols
get_client = server_module.get_client
_ok = server_module._ok
_register_tools = server_module._register_tools
_register_resources = server_module._register_resources
main = server_module.main
MCPApiClient = server_module.MCPApiClient

__all__ = [
    "get_client",
    "_ok",
    "_register_tools",
    "_register_resources",
    "main",
    "MCPApiClient",
]