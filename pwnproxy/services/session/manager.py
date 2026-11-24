import asyncio
import contextlib
import json
import logging
import shutil
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncEngine

from pwnproxy.services.session.storage import TokenStorage
from pwnproxy.services.session.store import TaskStore
from pwnproxy.shared.ports import DEFAULT_PROXY_PORT
from pwnproxy.shared.task_model import create_task_engine, init_task_db

logger = logging.getLogger(__name__)

SESSIONS_ROOT = Path.home() / ".pwnproxy" / "sessions"
DEFAULT_SESSION_NAME = "default"
LAST_SESSION_FILE = SESSIONS_ROOT / ".last_session"
AUTO_SAVE_INTERVAL = 60

#: Why active scanners are not receiving traffic, in words the user can act on.
#: Published verbatim by ``GET /sessions/scope``, ``GET /workers`` and the Web UI:
#: the client never recomputes the rule, it only shows these two sentences.
ACTIVE_SCAN_BLOCKED_SCOPE_OFF = (
    "Scope is off: active scanners only run on in-scope traffic. Turn the scope on."
)
ACTIVE_SCAN_BLOCKED_NO_RULES = (
    "Scope has no include rules: add at least one target to scan."
)


class ScopeConfig:
    def __init__(self, data: dict | None = None) -> None:
        d = data or {}
        self.in_scope: list[str] = d.get("in_scope", [])
        self.out_of_scope: list[str] = d.get("out_of_scope", [])
        enabled = d.get("enabled")
        if enabled is None:
            self.enabled = len(self.in_scope) > 0
        else:
            self.enabled = enabled
        if self.enabled and not self.in_scope:
            logger.warning("ScopeConfig enabled with empty in_scope list")

    def to_dict(self) -> dict:
        return {
            "in_scope": self.in_scope,
            "out_of_scope": self.out_of_scope,
            "enabled": self.enabled,
        }

    @staticmethod
    def _match(pattern: str, target: str) -> bool:
        from fnmatch import fnmatch
        if fnmatch(target, pattern):
            return True
        return bool(pattern.startswith("*.") and fnmatch(target, pattern[2:]))

    def _candidates(self, url: str) -> tuple[str, str, str]:
        """Return (netloc, hostname, full URL) candidates for scope matching.

        ``netloc`` is ``host:port`` (e.g. ``localhost:4280``) so a bare
        ``host:port`` pattern matches naturally; ``hostname`` drops the port so
        ``*.example.com`` keeps working; the full URL preserves Burp-style
        ``http://host:port/*`` patterns.
        """
        from urllib.parse import urlparse
        parsed = urlparse(url)
        netloc = parsed.netloc or ""
        host = parsed.hostname or ""
        return netloc, host, url

    def is_in_scope(self, url: str) -> bool:
        if not self.enabled:
            return True
        if not self.in_scope:
            return True
        candidates = self._candidates(url)
        for pattern in self.out_of_scope:
            if any(self._match(pattern, t) for t in candidates):
                return False
        return any(any(self._match(pattern, t) for t in candidates) for pattern in self.in_scope)

    def active_scan_blocked_reason(self) -> str | None:
        """Return why automatic scanning is not allowed right now, or ``None``.

        This is **the** rule for "may an automatically captured flow be handed
        to the scanners" (proxy, proxy worker and crawler all ask here, through
        :meth:`pwnproxy.shared.flow_filter.FlowFilter.allow_active_scan`).
        Capture and history are deliberately not part of it: with the scope off
        traffic keeps being captured, stored and shown in the UI.

        Returns:
            ``ACTIVE_SCAN_BLOCKED_SCOPE_OFF`` when the scope is disabled,
            ``ACTIVE_SCAN_BLOCKED_NO_RULES`` when it is enabled with no include
            rule (nothing would ever match), otherwise ``None``.
        """
        if not self.enabled:
            return ACTIVE_SCAN_BLOCKED_SCOPE_OFF
        if not self.in_scope:
            return ACTIVE_SCAN_BLOCKED_NO_RULES
        return None

    def active_scan_allowed(self) -> bool:
        """Whether active scanners may receive automatically captured traffic.

        Shorthand of ``active_scan_blocked_reason() is None`` so callers that
        only need the verdict cannot disagree with the ones that need the words.
        """
        return self.active_scan_blocked_reason() is None


class ProxyConfig:
    def __init__(self, data: dict | None = None) -> None:
        d = data or {}
        self.host: str = d.get("host", "127.0.0.1")
        self.port: int = d.get("port", DEFAULT_PROXY_PORT)
        self.ssl_insecure: bool = d.get("ssl_insecure", True)
        self.upstream: str | None = d.get("upstream", None)
        self.capture_enabled: bool = d.get("capture_enabled", True)

    def to_dict(self) -> dict:
        return {
            
            "ssl_insecure": self.ssl_insecure,
            "upstream": self.upstream,
            "capture_enabled": self.capture_enabled,
        }


class SessionManager:
    def __init__(
        self,
        traffic_engine: AsyncEngine,
        scanner_engine: AsyncEngine,
        token_storage: TokenStorage,
        on_session_change: Callable | None = None,
    ):
        self._traffic_engine = traffic_engine
        self._scanner_engine = scanner_engine
        self._token_storage = token_storage
        self._on_session_change = on_session_change

        self._active_name: str | None = None
        self._active_path: Path = SESSIONS_ROOT / "default"
        self._unsaved: bool = False
        self._save_lock = asyncio.Lock()
        self._auto_save_task: asyncio.Task | None = None
        self._running = False

        self.scope = ScopeConfig()
        self.proxy_config = ProxyConfig()
        self.task_store: TaskStore | None = None

        self._plugin_loader: any | None = None
        self._warned_legacy_plugins: bool = False
        self._interceptor_controller: any | None = None
        self._proxy_engine: any | None = None
        self._pending_module_state: dict | None = None
        self._crawler_engine = None
        self._on_scope_change: Callable | None = None

    def set_scope_change_handler(self, handler: Callable) -> None:
        """Register the callback fired after every scope update with the
        serialized scope dict (single consumer: the main-process event bus)."""
        self._on_scope_change = handler

    async def update_scope(self, data: dict) -> dict:
        """Single write point for scope (ownership matrix: SessionManager is
        the scope owner). Mutates the config, persists, and publishes via the
        scope-change handler. Returns the serialized scope.

        Transport layers (REST/TUI/CLI) MUST call this instead of assigning
        ``manager.scope`` directly — component fan-out (proxy/crawler) stays
        in the transport because it needs app-level component handles.
        """
        self.scope = ScopeConfig(data)
        await self.save()
        if self._on_scope_change:
            try:
                await self._on_scope_change(self.scope.to_dict())
            except Exception as exc:
                logger.warning("Scope change callback failed: %s", exc)
        return self.scope.to_dict()

    def set_module_providers(self, plugin_loader=None, interceptor_controller=None) -> None:
        self._plugin_loader = plugin_loader
        self._interceptor_controller = interceptor_controller
        if self._pending_module_state:
            asyncio.create_task(self._apply_module_state(self._pending_module_state))
            self._pending_module_state = None

    def set_proxy_engine(self, proxy_engine: any) -> None:
        self._proxy_engine = proxy_engine

    def get_proxy_engine(self):
        return self._proxy_engine

    def get_scope(self) -> ScopeConfig:
        """Return the scope in force, read on every call.

        ``update_scope`` and ``load`` *replace* the ``ScopeConfig`` instance, so
        anything that must follow the session scope live (the main-process
        ``FlowFilter`` that gates the auto-scan) holds this method, not an
        instance. Never returns a copy: the callers read, they do not mutate.
        """
        return self.scope

    async def _apply_proxy_config(self) -> None:
        if not self._proxy_engine:
            return
        if not getattr(self._proxy_engine, "running", False):
            return
        db_path = None
        scope_json = None
        if self._active_name and self._active_path:
            db_path = str(self._active_path / "traffic.db")
            scope_json = json.dumps(self.scope.to_dict())
        try:
            if hasattr(self._proxy_engine, "restart"):
                await self._proxy_engine.restart(self.proxy_config, db_path=db_path, scope_json=scope_json)
        except Exception as e:
            logger.error(f"Error restarting proxy: {e}")

    @property
    def active_name(self) -> str | None:
        return self._active_name

    @property
    def active_path(self) -> Path:
        return self._active_path

    @property
    def has_unsaved_changes(self) -> bool:
        return self._unsaved

    @property
    def has_active_session(self) -> bool:
        return self._active_name is not None

    async def start(self) -> None:
        self._running = True
        SESSIONS_ROOT.mkdir(parents=True, exist_ok=True)
        last = await self._read_last_session()
        if last and (SESSIONS_ROOT / last).exists():
            await self.load(last)
        self._auto_save_task = asyncio.create_task(self._auto_save_loop())

    async def stop(self) -> None:
        self._running = False
        if self._auto_save_task:
            self._auto_save_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._auto_save_task
        if self._unsaved and self._active_name:
            await self.save()

    async def create(self, name: str) -> None:
        path = SESSIONS_ROOT / name
        if path.exists():
            raise ValueError(f"Session '{name}' already exists")
        path.mkdir(parents=True)
        meta = {
            "name": name,
            "created_at": datetime.now().isoformat(),
            "last_modified": datetime.now().isoformat(),
            "version": 1,
        }
        (path / "session.json").write_text(json.dumps(meta, indent=2))
        scope = ScopeConfig()
        (path / "scope.json").write_text(json.dumps(scope.to_dict(), indent=2))
        (path / "modules.json").write_text(json.dumps(self._gather_module_state(), indent=2))
        self._active_name = name
        self._active_path = path
        self._unsaved = False
        self.scope = scope
        current_host = self.proxy_config.host
        current_port = self.proxy_config.port
        self.proxy_config = ProxyConfig()
        self.proxy_config.host = current_host
        self.proxy_config.port = current_port
        (path / "proxy.json").write_text(json.dumps(self.proxy_config.to_dict(), indent=2))
        await self._point_engines(path)
        await self._write_last_session(name)
        await self._apply_proxy_config()
        await self._notify_change()

    def _gather_module_state(self) -> dict:
        """Return the session-scoped module state.

        Plugin activation is **not** here any more: it is a machine-wide setting
        stored in ``~/.pwnproxy/config.toml`` (``[plugin.activation]``). Keeping
        it in ``modules.json`` mixed machine configuration with client evidence
        and, with one loader per process, made switching sessions silently change
        what scans the live traffic.
        """
        return {
            "interceptor_enabled": self._interceptor_controller.enabled if self._interceptor_controller else True,
        }

    async def _apply_module_state(self, state: dict) -> None:
        if self._interceptor_controller and "interceptor_enabled" in state:
            current = self._interceptor_controller.enabled
            wanted = state["interceptor_enabled"]
            if current != wanted:
                self._interceptor_controller.set_enabled(wanted)

        if "plugins" in state and not self._warned_legacy_plugins:
            # Sessions written before the activation moved to config.toml. The
            # key is ignored on purpose (the config file is the only source of
            # truth) and the file is left untouched; warn once, not per load.
            logger.warning(
                "Ignoring the legacy 'plugins' key in modules.json of session '%s': "
                "plugin activation now lives in ~/.pwnproxy/config.toml [plugin.activation]",
                self._active_name or "?",
            )
            self._warned_legacy_plugins = True

    async def save(self) -> None:
        if not self._active_name:
            return
        async with self._save_lock:
            self._active_path.mkdir(parents=True, exist_ok=True)
            meta = {
                "name": self._active_name,
                "last_modified": datetime.now().isoformat(),
                "version": 1,
            }
            (self._active_path / "session.json").write_text(
                json.dumps(meta, indent=2)
            )
            (self._active_path / "scope.json").write_text(
                json.dumps(self.scope.to_dict(), indent=2)
            )
            (self._active_path / "proxy.json").write_text(
                json.dumps(self.proxy_config.to_dict(), indent=2)
            )
            (self._active_path / "modules.json").write_text(
                json.dumps(self._gather_module_state(), indent=2)
            )
            await self._point_engines(self._active_path)
            self._unsaved = False

    async def load(self, name: str) -> None:
        path = SESSIONS_ROOT / name
        if not path.exists():
            raise ValueError(f"Session '{name}' not found")
        if self._unsaved:
            await self.save()
        self._active_name = name
        self._active_path = path
        await self._point_engines(path)
        scope_file = path / "scope.json"
        if scope_file.exists():
            self.scope = ScopeConfig(json.loads(scope_file.read_text()))
        else:
            self.scope = ScopeConfig()
            
        current_host = self.proxy_config.host
        current_port = self.proxy_config.port
        proxy_file = path / "proxy.json"
        if proxy_file.exists():
            self.proxy_config = ProxyConfig(json.loads(proxy_file.read_text()))
        else:
            self.proxy_config = ProxyConfig()
        self.proxy_config.host = current_host
        self.proxy_config.port = current_port
            
        modules_file = path / "modules.json"
        if modules_file.exists():
            state = json.loads(modules_file.read_text())
            if self._plugin_loader and self._interceptor_controller:
                await self._apply_module_state(state)
            else:
                self._pending_module_state = state
        self._unsaved = False
        await self._write_last_session(name)
        await self._apply_proxy_config()
        await self._notify_change()

    async def delete(self, name: str) -> None:
        path = SESSIONS_ROOT / name
        if not path.exists():
            raise ValueError(f"Session '{name}' not found")
        shutil.rmtree(path)
        if name == self._active_name:
            self._active_name = None
            self._active_path = SESSIONS_ROOT / "default"
            self._unsaved = False

    @staticmethod
    def list() -> list[dict]:
        if not SESSIONS_ROOT.exists():
            return []
        sessions = []
        for entry in sorted(SESSIONS_ROOT.iterdir()):
            if entry.is_dir():
                meta_file = entry / "session.json"
                meta = {}
                if meta_file.exists():
                    meta = json.loads(meta_file.read_text())
                sessions.append({
                    "name": entry.name,
                    "created_at": meta.get("created_at"),
                    "last_modified": meta.get("last_modified"),
                    "version": meta.get("version", 1),
                })
        return sessions

    @staticmethod
    async def rename(old: str, new: str) -> None:
        old_path = SESSIONS_ROOT / old
        new_path = SESSIONS_ROOT / new
        if not old_path.exists():
            raise ValueError(f"Session '{old}' not found")
        if new_path.exists():
            raise ValueError(f"Session '{new}' already exists")
        old_path.rename(new_path)
        meta_file = new_path / "session.json"
        if meta_file.exists():
            meta = json.loads(meta_file.read_text())
            meta["name"] = new
            meta["last_modified"] = datetime.now().isoformat()
            meta_file.write_text(json.dumps(meta, indent=2))

    async def _ensure_lazy(self) -> None:
        self._active_name = None
        self._active_path = SESSIONS_ROOT / "default"
        self._unsaved = False
        self.scope = ScopeConfig()
        self.proxy_config = ProxyConfig()
        await self._notify_change()

    async def _ensure_default(self) -> None:
        default = SESSIONS_ROOT / DEFAULT_SESSION_NAME
        if not default.exists():
            return
        self._active_name = DEFAULT_SESSION_NAME
        self._active_path = default
        self._unsaved = False
        await self._point_engines(default)
        scope_file = default / "scope.json"
        if scope_file.exists():
            self.scope = ScopeConfig(json.loads(scope_file.read_text()))
        else:
            self.scope = ScopeConfig()
            
        # Preserve host/port from current config
        current_host = self.proxy_config.host
        current_port = self.proxy_config.port
        proxy_file = default / "proxy.json"
        if proxy_file.exists():
            self.proxy_config = ProxyConfig(json.loads(proxy_file.read_text()))
        else:
            self.proxy_config = ProxyConfig()
        self.proxy_config.host = current_host
        self.proxy_config.port = current_port
            
        modules_file = default / "modules.json"
        if modules_file.exists():
            state = json.loads(modules_file.read_text())
            if self._plugin_loader and self._interceptor_controller:
                await self._apply_module_state(state)
            else:
                self._pending_module_state = state
        await self._apply_proxy_config()
        await self._notify_change()

    async def _point_engines(self, session_path: Path) -> None:
        from sqlalchemy.ext.asyncio import create_async_engine

        session_path.mkdir(parents=True, exist_ok=True)

        traffic_db = session_path / "traffic.db"
        traffic_url = f"sqlite+aiosqlite:///{traffic_db.absolute()}"
        new_traffic = create_async_engine(traffic_url, echo=False)
        await self._traffic_engine.dispose()
        self._traffic_engine = new_traffic
        from pwnproxy.shared.db import init_db
        await init_db(self._traffic_engine)

        scanner_db = session_path / "scanner_results.db"
        scanner_url = f"sqlite+aiosqlite:///{scanner_db.absolute()}"
        new_scanner = create_async_engine(scanner_url, echo=False)
        await self._scanner_engine.dispose()
        self._scanner_engine = new_scanner
        from pwnproxy.shared.findings.storage import FindingORM
        async with new_scanner.begin() as conn:
            await conn.run_sync(FindingORM.metadata.create_all)

        tokens_db = session_path / "tokens.db"
        await self._token_storage.repoint(str(tokens_db.absolute()))

        task_engine = create_task_engine(str(session_path))
        await init_task_db(task_engine)
        self.task_store = TaskStore(task_engine)
        await self.task_store.init()

        crawler_db = session_path / "crawler.db"
        crawler_url = f"sqlite+aiosqlite:///{crawler_db.absolute()}"
        if self._crawler_engine is not None:
            await self._crawler_engine.dispose()
        self._crawler_engine = create_async_engine(crawler_url, echo=False)

    async def _write_last_session(self, name: str) -> None:
        SESSIONS_ROOT.mkdir(parents=True, exist_ok=True)
        (LAST_SESSION_FILE).write_text(name)

    async def _read_last_session(self) -> str | None:
        if LAST_SESSION_FILE.exists():
            return LAST_SESSION_FILE.read_text().strip()
        return None

    async def _auto_save_loop(self) -> None:
        while self._running:
            await asyncio.sleep(AUTO_SAVE_INTERVAL)
            if self._unsaved and self._active_name:
                try:
                    await self.save()
                    logger.debug(f"Auto-saved session '{self._active_name}'")
                except Exception as e:
                    logger.error(f"Auto-save failed: {e}")

    async def _notify_change(self) -> None:
        if self._on_session_change:
            await self._on_session_change(self._active_name)

    def mark_unsaved(self) -> None:
        self._unsaved = True

    def get_traffic_engine(self) -> AsyncEngine:
        return self._traffic_engine

    def get_scanner_engine(self) -> AsyncEngine:
        return self._scanner_engine

    def get_token_storage(self) -> TokenStorage:
        return self._token_storage

    def get_crawler_engine(self):
        return self._crawler_engine
