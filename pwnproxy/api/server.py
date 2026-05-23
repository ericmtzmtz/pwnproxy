import asyncio
import logging
from pathlib import Path
from typing import Optional

import uvicorn
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from pwnproxy.api.main import app
from pwnproxy.core.hooks import HookBus

logger = logging.getLogger(__name__)


def _create_scanner_engine() -> AsyncEngine:
    db_path = Path.home() / ".pwnproxy" / "scanner_results.db"
    db_url = f"sqlite+aiosqlite:///{db_path.absolute()}"
    return create_async_engine(db_url, echo=False)


def _create_traffic_engine() -> AsyncEngine:
    from pwnproxy.core.db import create_engine as make_traffic_engine
    return make_traffic_engine()


def _create_sessions_engine() -> AsyncEngine:
    db_path = Path.home() / ".pwnproxy" / "sessions.db"
    db_url = f"sqlite+aiosqlite:///{db_path.absolute()}"
    return create_async_engine(db_url, echo=False)


async def start_api_server(
    hook_bus: HookBus,
    traffic_engine: Optional[AsyncEngine] = None,
    scanner_engine: Optional[AsyncEngine] = None,
    token_storage=None,
    interceptor_controller=None,
    repeater_engine=None,
    intruder_engine=None,
    host: str = "127.0.0.1",
    port: int = 8000,
) -> asyncio.Task:
    """Start the FastAPI/Uvicorn server in a background task."""
    if traffic_engine is None:
        traffic_engine = _create_traffic_engine()
    if scanner_engine is None:
        scanner_engine = _create_scanner_engine()

    app.state.hook_bus = hook_bus
    app.state.traffic_engine = traffic_engine
    app.state.scanner_engine = scanner_engine
    app.state.token_storage = token_storage
    app.state.interceptor_controller = interceptor_controller
    app.state.repeater_engine = repeater_engine
    app.state.intruder_engine = intruder_engine

    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="info",
        access_log=False,
    )
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    logger.info(f"API server started on {host}:{port}")
    return task
