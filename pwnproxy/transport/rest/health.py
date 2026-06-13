import asyncio
import logging
from typing import Optional

from fastapi import APIRouter, Request

from pwnproxy.services.plugins.loader import PluginLoader

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["health"])


def _get_version() -> str:
    try:
        from importlib.metadata import version
        return version("pwnproxy")
    except Exception:
        return "0.1.0"


async def _check_port(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


@router.get("/health")
async def health_check(request: Request):
    proxy_port = getattr(request.app.state, "proxy_port", 8080)
    proxy_ok = await _check_port("127.0.0.1", proxy_port)

    loader: Optional[PluginLoader] = getattr(request.app.state, "plugin_loader", None)
    scanner_names = []
    plugin_names = []
    if loader is not None:
        active = loader.list_active()
        scanner_names = [p["name"] for p in active if p.get("category") == "scanner" and not p.get("disabled")]
        plugin_names = [p["name"] for p in active]

    checks = {
        "api": {"status": "ok", "message": "API is running"},
        "proxy": {
            "status": "ok" if proxy_ok else "down",
            "message": "Proxy is accepting connections" if proxy_ok else "Proxy is not responding",
        },
        "scanners": {
            "status": "ok" if scanner_names else "degraded",
            "count": len(scanner_names),
            "active": scanner_names,
            "message": f"{len(scanner_names)} scanner(s) loaded" if scanner_names else "No scanners loaded",
        },
        "plugins": {
            "status": "ok",
            "count": len(plugin_names),
            "active": plugin_names,
            "message": f"{len(plugin_names)} plugin(s) loaded",
        },
    }

    overall = "ok"
    for name, check in checks.items():
        if check["status"] == "down":
            overall = "degraded"
            break

    return {
        "status": overall,
        "version": _get_version(),
        "checks": checks,
    }
