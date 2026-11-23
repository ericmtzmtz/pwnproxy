"""Guards for the default ports of every pwnproxy service.

Two rules are enforced here:

1. **One source of truth** (:class:`TestNoStalePortLiterals`). The default ports
   live only in ``pwnproxy/shared/ports.py``. Any other file under ``pwnproxy/``
   or ``apps/`` that hardcodes an old port in a *port context* (``":8080"``,
   ``port=8080``, ``= 8000``, ``Option(8080`` …) fails the guard, listing
   ``archivo:línea``. Legitimate false positives are enumerated in
   :data:`WHITELIST` with the reason they cannot (or must not) change.
2. **The defaults come from the constants** (:class:`TestDefaultsUseConstants`).
   The CLI options, ``ProxyEngine.__init__`` and the API server compare equal to
   ``pwnproxy.shared.ports`` — so bumping the constant really moves every
   surface, and a hardcoded number cannot sneak back in.

The scan is textual on purpose: an AST walk cannot see a port hidden inside a
URL string (``f"http://127.0.0.1:{port}"``) nor inside a shell entrypoint, which
is exactly where the stale numbers used to live.
"""

from __future__ import annotations

import importlib
import inspect
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# ---------------------------------------------------------------------------
# Rule 1 — no stale port literals in a port context
# ---------------------------------------------------------------------------

#: Ports that must never be hardcoded again. They are the *old* defaults; the
#: current ones live in ``pwnproxy.shared.ports`` and are not scanned for,
#: because the whole point is that they have a single home. ``18080`` and
#: ``8888`` are the third and fourth copies of the SSRF callback port that used
#: to exist (plugin payloads vs. ``HTTPCallbackServer``), which made ``start``
#: listen on one port while the scanner probed another.
STALE_PORTS = ("8080", "8000", "4321", "18081", "18080", "8888")

#: Directories walked by the guard, relative to the repo root.
SCANNED_ROOTS = ("pwnproxy", "apps")

#: Directory names pruned at any depth: build output and installed deps.
PRUNED_DIR_NAMES = {
    "node_modules",
    "dist",
    ".astro",
    "__pycache__",
    ".venv",
    "venv",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".git",
}

#: File suffixes inspected. Binary/asset files carry no port context.
SCANNED_SUFFIXES = {
    ".py",
    ".ts",
    ".tsx",
    ".mjs",
    ".js",
    ".astro",
    ".sh",
    ".ps1",
    ".yml",
    ".yaml",
    ".toml",
    ".json",
    ".html",
    ".cfg",
    ".ini",
}

_PORT = "(?:" + "|".join(STALE_PORTS) + ")"

#: Each entry is one way a service port is spelled in this repo.
PORT_CONTEXT_PATTERNS = (
    # http://127.0.0.1:8000/api/v1, ws://host:8000, "--callback-port", "18081"
    re.compile(rf"[:\s]{_PORT}\b"),
    # port=8080, port: 8080, "port": 8000, listen_port=18081, PROXY_PORT:-8080
    re.compile(rf"(?i)port[\"']?\s*[=:]-?\s*{_PORT}\b"),
    # typer.Option(8080, "--proxy-port"), SomeServer(8000)
    re.compile(rf"\(\s*{_PORT}\s*[,)]"),
    # listen_port = 4321, default=8000
    re.compile(rf"=\s*{_PORT}\b"),
    # os.environ.get("PWNPROXY_OOB_PORT", "8888") — the port as a bare string
    re.compile(rf"[\"']{_PORT}[\"']"),
)

#: ``archivo:línea`` entries allowed to keep a stale literal, with the reason.
#: Every entry is a *legitimate* false positive: a third-party example or a
#: value that is not a pwnproxy service port at all.
WHITELIST: dict[str, str] = {
    "apps/web/src/pages/settings/index.astro:49": (
        "placeholder http://proxy:8080 — ejemplo de un proxy de upstream ajeno, "
        "no el puerto de pwnproxy"
    ),
    "pwnproxy/shared/scan/stages/sqli_stages.py:394": (
        "VARCHAR(8000) — tipo de columna T-SQL, no un puerto"
    ),
    "pwnproxy/transport/rest/session.py:15": (
        "docstring con un ejemplo de patrón de scope ('http://host:8080/*') "
        "sobre un host ajeno, no el puerto de pwnproxy"
    ),
}

#: Files whose ports are arbitrary values passed explicitly by the test itself
#: (never the default under test), so the guard has nothing to protect there.
WHITELISTED_FILES: dict[str, str] = {
    "apps/mcp/tests/test_server.py": (
        "URLs de API arbitrarias que la propia prueba pasa a MCPApiClient; "
        "no comprueban el puerto por omisión"
    ),
}


def _iter_scanned_files() -> list[Path]:
    """Return every source file the guard inspects, sorted for stable output."""
    files: list[Path] = []
    for root_name in SCANNED_ROOTS:
        root = REPO_ROOT / root_name
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            relative_parts = path.relative_to(REPO_ROOT).parts
            if any(part in PRUNED_DIR_NAMES for part in relative_parts):
                continue
            if path.suffix.lower() not in SCANNED_SUFFIXES:
                continue
            files.append(path)
    return sorted(files)


def _port_literals(text: str) -> list[tuple[int, str]]:
    """Return ``(lineno, matched_text)`` for each stale port in a port context."""
    hits: list[tuple[int, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for pattern in PORT_CONTEXT_PATTERNS:
            match = pattern.search(line)
            if match:
                hits.append((lineno, match.group(0).strip()))
                break
    return hits


def _scan_port_literals(files: list[Path] | None = None) -> list[str]:
    """Collect ``archivo:línea (literal)`` for every non-whitelisted hit."""
    violations: list[str] = []
    for path in files if files is not None else _iter_scanned_files():
        relative = path.relative_to(REPO_ROOT).as_posix()
        if relative in WHITELISTED_FILES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for lineno, literal in _port_literals(text):
            key = f"{relative}:{lineno}"
            if key in WHITELIST:
                continue
            violations.append(f"{key} ({literal!r})")
    return violations


class TestNoStalePortLiterals:
    def test_no_stale_port_literals_outside_the_whitelist(self):
        violations = _scan_port_literals()
        assert violations == [], (
            "Los puertos por omisión viven solo en pwnproxy/shared/ports.py. "
            "Usa las constantes DEFAULT_*_PORT en vez de literales:\n"
            + "\n".join(violations)
        )

    def test_guard_detects_every_port_context(self, tmp_path):
        """The guard must fail on the shapes the stale numbers actually used."""
        sample = tmp_path / "sample.py"
        sample.write_text(
            "proxy_port: int = typer.Option(8080, \"--proxy-port\")\n"  # 1
            "api_url = \"http://127.0.0.1:8000/api/v1\"\n"  # 2
            "listen_port = 4321\n"  # 3
            "callback = {\"port\": 18081}\n"  # 4
            "web_ui = \"http://127.0.0.1:4321\"\n"  # 5
            "column = \"VARCHAR(8000)\"\n"  # 6 — false positive, whitelisted
            "elapsed = 3000\n",  # 7 — not a port
            encoding="utf-8",
        )
        hits = [lineno for lineno, _ in _port_literals(sample.read_text(encoding="utf-8"))]
        assert hits == [1, 2, 3, 4, 5, 6]

    def test_guard_ignores_non_port_numbers(self, tmp_path):
        sample = tmp_path / "sample.py"
        sample.write_text(
            "timeout_ms = 3000\n"
            "wordlist = \"raft-medium-directories-8080.txt\"\n"
            "offset = 180800\n"
            "width = \"w-[4320px]\"\n",
            encoding="utf-8",
        )
        assert _port_literals(sample.read_text(encoding="utf-8")) == []

    def test_whitelist_entries_point_at_a_real_violation(self):
        """A stale whitelist entry would hide a regression: each must still hit."""
        orphans: list[str] = []
        for key in WHITELIST:
            relative, _, lineno_text = key.rpartition(":")
            path = REPO_ROOT / relative
            if not path.is_file():
                orphans.append(f"{key} (archivo inexistente)")
                continue
            lines = path.read_text(encoding="utf-8").splitlines()
            lineno = int(lineno_text)
            if lineno > len(lines):
                orphans.append(f"{key} (el archivo tiene {len(lines)} líneas)")
                continue
            if not _port_literals(lines[lineno - 1]):
                orphans.append(f"{key} (la línea ya no tiene un literal de puerto)")
        assert orphans == [], "Entradas obsoletas en la lista blanca:\n" + "\n".join(orphans)


# ---------------------------------------------------------------------------
# Rule 2 — every default comes from pwnproxy.shared.ports
# ---------------------------------------------------------------------------


class TestDefaultsUseConstants:
    def test_single_source_module_values(self):
        from pwnproxy.shared import ports

        assert (
            ports.DEFAULT_PROXY_PORT,
            ports.DEFAULT_API_PORT,
            ports.DEFAULT_WEB_PORT,
            ports.DEFAULT_CALLBACK_PORT,
        ) == (17170, 17171, 17172, 17173)

    def test_api_base_is_built_from_the_api_port(self):
        from pwnproxy.shared import ports

        expected = f"http://127.0.0.1:{ports.DEFAULT_API_PORT}/api/v1"
        assert expected == ports.DEFAULT_API_BASE

    def test_proxy_engine_default_port(self):
        from pwnproxy.services.proxy.engine import ProxyEngine
        from pwnproxy.shared import ports

        parameter = inspect.signature(ProxyEngine.__init__).parameters["port"]
        assert parameter.default == ports.DEFAULT_PROXY_PORT

    def test_api_server_default_ports(self):
        from apps.api.server import start_api_server
        from pwnproxy.shared import ports

        parameters = inspect.signature(start_api_server).parameters
        assert parameters["port"].default == ports.DEFAULT_API_PORT
        assert parameters["proxy_port"].default == ports.DEFAULT_PROXY_PORT

    def test_cli_start_option_defaults(self):
        from typer.models import OptionInfo

        from pwnproxy.shared import ports

        module = importlib.import_module("apps.terminal.cli.start")
        parameters = inspect.signature(module.start).parameters
        defaults = {}
        for name in ("proxy_port", "api_port", "callback_port"):
            default = parameters[name].default
            assert isinstance(default, OptionInfo), f"{name} is not a typer.Option"
            defaults[name] = default.default
        assert defaults == {
            "proxy_port": ports.DEFAULT_PROXY_PORT,
            "api_port": ports.DEFAULT_API_PORT,
            "callback_port": ports.DEFAULT_CALLBACK_PORT,
        }

    def test_session_proxy_config_default_port(self):
        from pwnproxy.services.session.manager import ProxyConfig
        from pwnproxy.shared import ports

        assert ProxyConfig().port == ports.DEFAULT_PROXY_PORT

    def test_proxy_worker_cli_default_port(self):
        from pwnproxy.services.proxy import proxy_worker
        from pwnproxy.shared import ports

        argv = sys.argv
        sys.argv = ["proxy_worker"]
        try:
            args = proxy_worker._parse_args()
        finally:
            sys.argv = argv
        assert args.listen_port == ports.DEFAULT_PROXY_PORT

    def test_health_falls_back_to_the_default_proxy_port(self):
        from pwnproxy.shared import ports

        module = importlib.import_module("pwnproxy.transport.rest.health")
        source = inspect.getsource(module.health_check)
        assert "DEFAULT_PROXY_PORT" in source
        assert ports.DEFAULT_PROXY_PORT == 17170


class TestSsrfCallbackPortIsCongruent:
    """The OOB payload port and the OOB listener port must be the same number.

    They used to be three unrelated literals (18080 in the scanner, 8888 in
    ``HTTPCallbackServer``, 18081 in the CLI), so ``pwnproxy start`` listened on
    one port while every blind-SSRF payload knocked on another and no callback
    was ever confirmed.
    """

    def test_callback_server_defaults_to_the_shared_constant(self):
        from pwnproxy.shared import ports
        from pwnproxy.shared.http_server import HTTPCallbackServer

        assert HTTPCallbackServer().port == ports.DEFAULT_CALLBACK_PORT

    def test_callback_server_env_override_still_wins(self, monkeypatch):
        module = importlib.import_module("pwnproxy.shared.http_server")
        monkeypatch.setenv("PWNPROXY_OOB_PORT", "19990")
        try:
            reloaded = importlib.reload(module)
            assert reloaded.HTTPCallbackServer().port == 19990
        finally:
            monkeypatch.delenv("PWNPROXY_OOB_PORT", raising=False)
            importlib.reload(module)

    def test_ssrf_plugin_without_config_uses_the_shared_constant(self):
        import asyncio

        from pwnproxy.plugins.core.base import PluginContext
        from pwnproxy.plugins.scanners.ssrf.plugin import SSRFScannerPlugin
        from pwnproxy.shared import ports

        plugin = SSRFScannerPlugin()
        plugin.context = PluginContext(config={})

        async def _load():
            await plugin.on_load()

        asyncio.run(_load())
        assert plugin._scanner._callback_port == ports.DEFAULT_CALLBACK_PORT

    def test_ssrf_stages_default_to_the_shared_constant(self):
        import asyncio

        from pwnproxy.shared import ports
        from pwnproxy.shared.scan.replayer import RequestReplayer
        from pwnproxy.shared.scan.stages.ssrf_stages import SsrfOOBStage, SsrfSimpleStage

        replayer = RequestReplayer()
        try:
            assert SsrfSimpleStage(replayer)._callback_port == ports.DEFAULT_CALLBACK_PORT
            assert SsrfOOBStage(replayer)._callback_port == ports.DEFAULT_CALLBACK_PORT
        finally:
            asyncio.run(replayer.close())

    def test_start_hands_the_callback_port_to_the_discovered_ssrf_plugin(self):
        """``pwnproxy start --callback-port`` must reach the plugin's payloads."""
        import asyncio

        from apps.terminal.cli.start import _plugin_configs
        from pwnproxy.plugins.core.loader import PluginLoader
        from pwnproxy.shared.hooks import HookBus

        async def _discover():
            loader = PluginLoader(hook_bus=HookBus())
            # Same wiring `start` performs before plugin_loader.start().
            loader.plugin_configs = _plugin_configs(19991)
            await loader.discover_scanners()
            return loader

        loader = asyncio.run(_discover())
        assert loader.plugin_configs == {"ssrf": {"callback_port": 19991}}
        assert loader._plugins["ssrf"]._scanner._callback_port == 19991
        # Other scanners keep an empty config (nothing else needs runtime values).
        assert loader._plugins["sqli"].context.config == {}



class TestMirroredDefaults:
    """Ports copied where Python cannot be imported must not drift.

    The Web UI (TypeScript), the Docker entrypoint and the standalone
    ``pwnproxy-mcp`` package cannot import ``pwnproxy.shared.ports``, so they
    mirror the numbers. These tests are the bridge: bumping a constant without
    updating the mirror fails here.
    """

    def test_mcp_package_mirrors_the_api_port(self):
        from pwnproxy.shared import ports

        server = (REPO_ROOT / "apps/mcp/src/pwnproxy_mcp/server.py").read_text(encoding="utf-8")
        match = re.search(r"^DEFAULT_API_PORT = (\d+)$", server, re.MULTILINE)
        assert match is not None, "apps/mcp/src/pwnproxy_mcp/server.py no define DEFAULT_API_PORT"
        assert int(match.group(1)) == ports.DEFAULT_API_PORT

    def test_web_ui_mirrors_the_api_and_web_ports(self):
        from pwnproxy.shared import ports

        web = REPO_ROOT / "apps/web"
        core = (web / "src/core/index.ts").read_text(encoding="utf-8")
        astro = (web / "astro.config.mjs").read_text(encoding="utf-8")
        dev_script = (web / "scripts/dev.mjs").read_text(encoding="utf-8")

        found = {
            "core_api": int(re.search(r"const DEFAULT_API_PORT = (\d+);", core).group(1)),
            "astro_dev_server": int(re.search(r"port: (\d+),", astro).group(1)),
            "dev_script_api": int(re.search(r'PWNPROXY_API_PORT \?\? "(\d+)"', dev_script).group(1)),
        }
        assert found == {
            "core_api": ports.DEFAULT_API_PORT,
            "astro_dev_server": ports.DEFAULT_WEB_PORT,
            "dev_script_api": ports.DEFAULT_API_PORT,
        }

    def test_docker_defaults_mirror_the_constants(self):
        from pwnproxy.shared import ports

        docker = REPO_ROOT / "deploy/docker"
        text = (docker / "docker-compose.yml").read_text(encoding="utf-8") + (
            docker / "docker-entrypoint.sh"
        ).read_text(encoding="utf-8")

        found = {
            name: int(value)
            for name, value in re.findall(
                r"\$\{?(PROXY_PORT|API_PORT|CALLBACK_PORT|WEB_PORT):-(\d+)\}?", text
            )
        }
        assert found == {
            "PROXY_PORT": ports.DEFAULT_PROXY_PORT,
            "API_PORT": ports.DEFAULT_API_PORT,
            "CALLBACK_PORT": ports.DEFAULT_CALLBACK_PORT,
            "WEB_PORT": ports.DEFAULT_WEB_PORT,
        }
