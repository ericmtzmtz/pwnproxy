import asyncio
import json
import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from sqlalchemy.ext.asyncio import AsyncEngine
from sqlalchemy import create_engine as create_sync_engine

from pwnproxy.services.session.storage import TokenStorage
from pwnproxy.shared.task_model import create_task_engine, init_task_db
from pwnproxy.services.session.store import TaskStore

logger = logging.getLogger(__name__)

SESSIONS_ROOT = Path.home() / ".pwnproxy" / "sessions"
DEFAULT_SESSION_NAME = "default"
LAST_SESSION_FILE = SESSIONS_ROOT / ".last_session"
AUTO_SAVE_INTERVAL = 60


class ScopeConfig:
    def __init__(self, data: Optional[dict] = None) -> None:
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
        if pattern.startswith("*.") and fnmatch(target, pattern[2:]):
            return True
        return False

    def is_in_scope(self, url: str) -> bool:
        if not self.enabled:
            return True
        if not self.in_scope:
            return True
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname or ""
        combined = url  # Use full URL including query string
        for pattern in self.out_of_scope:
            if self._match(pattern, combined) or self._match(pattern, host):
                return False
        for pattern in self.in_scope:
            if self._match(pattern, combined) or self._match(pattern, host):
                return True
        return False


class ProxyConfig:
    def __init__(self, data: Optional[dict] = None) -> None:
        d = data or {}
        self.host: str = d.get("host", "127.0.0.1")
        self.port: int = d.get("port", 8080)
        self.ssl_insecure: bool = d.get("ssl_insecure", True)
        self.upstream: Optional[str] = d.get("upstream", None)
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
        on_session_change: Optional[Callable] = None,
    ):
        self._traffic_engine = traffic_engine
        self._scanner_engine = scanner_engine
        self._token_storage = token_storage
        self._on_session_change = on_session_change

        self._active_name: Optional[str] = None
        self._active_path: Path = SESSIONS_ROOT / "default"
        self._unsaved: bool = False
        self._save_lock = asyncio.Lock()
        self._auto_save_task: Optional[asyncio.Task] = None
        self._running = False

        self.scope = ScopeConfig()
        self.proxy_config = ProxyConfig()
        self.task_store: Optional[TaskStore] = None

        self._plugin_loader: Optional[any] = None
        self._interceptor_controller: Optional[any] = None
        self._proxy_engine: Optional[any] = None
        self._pending_module_state: Optional[dict] = None
        self._crawler_engine = None
        self._on_scope_change: Optional[Callable] = None

    def set_scope_change_handler(self, handler: Callable) -> None:
        """Register the callback fired after every scope update with the
        serialized scope dict (single consumer: the main-process event bus)."""
        self._on_scope_change = handler

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
    def active_name(self) -> Optional[str]:
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
            try:
                await self._auto_save_task
            except (asyncio.CancelledError, Exception):
                pass
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
        plugins = {}
        if self._plugin_loader:
            for name in self._plugin_loader.list_plugins():
                info = self._plugin_loader.get_plugin_info(name)
                if info:
                    plugins[info["name"]] = {"disabled": info.get("disabled", False)}
        return {
            "interceptor_enabled": self._interceptor_controller.enabled if self._interceptor_controller else True,
            "plugins": plugins,
        }

    async def _apply_module_state(self, state: dict) -> None:
        if self._interceptor_controller and "interceptor_enabled" in state:
            current = self._interceptor_controller.enabled
            wanted = state["interceptor_enabled"]
            if current != wanted:
                self._interceptor_controller.set_enabled(wanted)

        if self._plugin_loader and "plugins" in state:
            for name, cfg in state["plugins"].items():
                was_disabled = self._plugin_loader.watchdog_stats().get("disabled", [])
                if cfg.get("disabled", False) and name not in was_disabled:
                    self._plugin_loader.deactivate(name)
                elif not cfg.get("disabled", False) and name in was_disabled:
                    await self._plugin_loader.activate(name)

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

    async def _read_last_session(self) -> Optional[str]:
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
