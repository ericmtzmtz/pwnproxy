import asyncio
import json
import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from sqlalchemy.ext.asyncio import AsyncEngine
from sqlalchemy import create_engine as create_sync_engine

from pwnproxy.modules.session_manager.storage import TokenStorage

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
        self.include_subdomains: bool = d.get("include_subdomains", True)
        self.ports: list[int] = d.get("ports", [80, 443])
        self.enabled: bool = d.get("enabled", False)

    def to_dict(self) -> dict:
        return {
            "in_scope": self.in_scope,
            "out_of_scope": self.out_of_scope,
            "include_subdomains": self.include_subdomains,
            "ports": self.ports,
            "enabled": self.enabled,
        }

    def is_in_scope(self, url: str) -> bool:
        if not self.enabled:
            return True
        if not self.in_scope:
            return True
        from urllib.parse import urlparse
        from fnmatch import fnmatch
        parsed = urlparse(url)
        host = parsed.hostname or ""
        for pattern in self.out_of_scope:
            if fnmatch(f"{parsed.scheme}://{host}{parsed.path}", pattern):
                return False
            if fnmatch(host, pattern):
                return False
        for pattern in self.in_scope:
            if fnmatch(f"{parsed.scheme}://{host}{parsed.path}", pattern):
                return True
            if fnmatch(host, pattern):
                return True
        return False


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

        self._active_name: str = DEFAULT_SESSION_NAME
        self._active_path: Path = SESSIONS_ROOT / DEFAULT_SESSION_NAME
        self._unsaved: bool = False
        self._save_lock = asyncio.Lock()
        self._auto_save_task: Optional[asyncio.Task] = None
        self._running = False

        self.scope = ScopeConfig()

    @property
    def active_name(self) -> str:
        return self._active_name

    @property
    def active_path(self) -> Path:
        return self._active_path

    @property
    def has_unsaved_changes(self) -> bool:
        return self._unsaved

    async def start(self) -> None:
        self._running = True
        SESSIONS_ROOT.mkdir(parents=True, exist_ok=True)
        last = await self._read_last_session()
        if last and (SESSIONS_ROOT / last).exists():
            await self.load(last)
        else:
            await self._ensure_default()
        self._auto_save_task = asyncio.create_task(self._auto_save_loop())

    async def stop(self) -> None:
        self._running = False
        if self._auto_save_task:
            self._auto_save_task.cancel()
            try:
                await self._auto_save_task
            except (asyncio.CancelledError, Exception):
                pass
        if self._unsaved:
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
        self._active_name = name
        self._active_path = path
        self._unsaved = False
        self.scope = scope
        await self._write_last_session(name)
        await self._notify_change()

    async def save(self) -> None:
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
        self._unsaved = False
        await self._write_last_session(name)
        await self._notify_change()

    async def delete(self, name: str) -> None:
        path = SESSIONS_ROOT / name
        if not path.exists():
            raise ValueError(f"Session '{name}' not found")
        if name == self._active_name:
            if self._unsaved:
                await self.save()
            shutil.rmtree(path)
            await self._ensure_default()
        else:
            shutil.rmtree(path)

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

    async def _ensure_default(self) -> None:
        default = SESSIONS_ROOT / DEFAULT_SESSION_NAME
        if not default.exists():
            default.mkdir(parents=True)
            meta = {
                "name": DEFAULT_SESSION_NAME,
                "created_at": datetime.now().isoformat(),
                "last_modified": datetime.now().isoformat(),
                "version": 1,
            }
            (default / "session.json").write_text(json.dumps(meta, indent=2))
            (default / "scope.json").write_text(
                json.dumps(ScopeConfig().to_dict(), indent=2)
            )
        self._active_name = DEFAULT_SESSION_NAME
        self._active_path = default
        self._unsaved = False
        await self._point_engines(default)
        scope_file = default / "scope.json"
        if scope_file.exists():
            self.scope = ScopeConfig(json.loads(scope_file.read_text()))
        else:
            self.scope = ScopeConfig()
        await self._notify_change()

    async def _point_engines(self, session_path: Path) -> None:
        from sqlalchemy.ext.asyncio import create_async_engine

        session_path.mkdir(parents=True, exist_ok=True)

        traffic_db = session_path / "traffic.db"
        traffic_url = f"sqlite+aiosqlite:///{traffic_db.absolute()}"
        new_traffic = create_async_engine(traffic_url, echo=False)
        await self._traffic_engine.dispose()
        self._traffic_engine = new_traffic
        from pwnproxy.core.db import init_db
        await init_db(self._traffic_engine)

        scanner_db = session_path / "scanner_results.db"
        scanner_url = f"sqlite+aiosqlite:///{scanner_db.absolute()}"
        new_scanner = create_async_engine(scanner_url, echo=False)
        await self._scanner_engine.dispose()
        self._scanner_engine = new_scanner

        tokens_db = session_path / "tokens.db"
        await self._token_storage.repoint(str(tokens_db.absolute()))

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
            if self._unsaved:
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
