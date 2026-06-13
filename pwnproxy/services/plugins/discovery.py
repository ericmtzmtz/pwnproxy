import importlib.metadata
import json
import logging
import subprocess
import sys
from typing import Optional

logger = logging.getLogger(__name__)

PYPI_PREFIX = "pwnproxy-"
PYPI_JSON_API = "https://pypi.org/pypi"


def discover_installed() -> list[dict]:
    packages = []
    for dist in importlib.metadata.distributions():
        name = dist.metadata.get("Name", "")
        if not name.lower().startswith(PYPI_PREFIX):
            continue
        pwnproxy_meta = _read_pwnproxy_metadata(dist)
        if pwnproxy_meta is None:
            continue
        packages.append({
            "name": name,
            "version": dist.version,
            "summary": dist.metadata.get("Summary", ""),
            **pwnproxy_meta,
        })
    return packages


def _read_pwnproxy_metadata(dist) -> Optional[dict]:
    try:
        text = dist.read_text("pyproject.toml")
        if text is None:
            return None
        import tomllib
        data = tomllib.loads(text)
        return data.get("tool", {}).get("pwnproxy")
    except Exception:
        try:
            text = dist.read_text("pwnproxy.json")
            if text:
                return json.loads(text)
        except Exception:
            pass
    return None


def search_pypi(term: str, registry_url: Optional[str] = None) -> list[dict]:
    if registry_url:
        return _search_registry(registry_url, term)
    return _search_pypi_xmlrpc(term)


def _search_pypi_xmlrpc(term: str) -> list[dict]:
    try:
        import xmlrpc.client
        client = xmlrpc.client.ServerProxy("https://pypi.python.org/pypi")
        results = client.search({"name": f"{PYPI_PREFIX}{term}"}, "or")
        return [
            {"name": r["name"], "version": r.get("version", ""), "summary": r.get("summary", "")}
            for r in results
            if r["name"].lower().startswith(PYPI_PREFIX)
        ]
    except Exception as e:
        logger.warning("PyPI XML-RPC search failed: %s", e)
        return []


def _search_registry(registry_url: str, term: str) -> list[dict]:
    import httpx
    try:
        resp = httpx.get(f"{registry_url.rstrip('/')}/api/v1/search", params={"q": term}, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.warning("Registry search failed: %s", e)
        return []


def install_package(name: str) -> bool:
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", name],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            logger.error("pip install failed: %s", result.stderr)
            return False
        return True
    except subprocess.TimeoutExpired:
        logger.error("pip install timed out")
        return False
    except Exception as e:
        logger.error("pip install error: %s", e)
        return False
