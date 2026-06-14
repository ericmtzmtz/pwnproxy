"""Compatibility package to expose pwnproxy-mcp as pwnproxy_mcp.
This allows imports expecting the underscore module name to work.
"""
import importlib.util
import sys
from pathlib import Path

# Resolve the actual package directory (apps/mcp)
_pkg_path = Path(__file__).parent.parent / "apps" / "mcp"
_spec = importlib.util.spec_from_file_location("pwnproxy_mcp", _pkg_path / "src" / "pwnproxy_mcp" / "__init__.py")
module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(module)  # type: ignore
sys.modules[__name__] = module
