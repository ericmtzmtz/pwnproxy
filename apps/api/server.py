import asyncio
import logging
from pathlib import Path
from typing import Optional

import uvicorn
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from pwnproxy.transport.rest.app import app
from pwnproxy.shared.hooks import HookBus
from pwnproxy.ai.llm import create_client_from_config
from pwnproxy.ai.llm.usage import UsageLedger, default_ledger_engine

logger = logging.getLogger(__name__)


# Suppress uvicorn/starlette CancelledError during shutdown
class _SuppressCancelledError(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if "CancelledError" in record.getMessage():
            return False
        if record.exc_text and "CancelledError" in record.exc_text:
            return False
        if record.exc_info and record.exc_info[0] is asyncio.CancelledError:
            return False
        return True


logging.getLogger("uvicorn.error").addFilter(_SuppressCancelledError())


def _create_scanner_engine(session_path: Optional[str] = None) -> AsyncEngine:
    if session_path:
        db_path = Path(session_path) / "scanner_results.db"
    else:
        db_path = Path.home() / ".pwnproxy" / "scanner_results.db"
    db_url = f"sqlite+aiosqlite:///{db_path.absolute()}"
    return create_async_engine(db_url, echo=False)


def _create_traffic_engine() -> AsyncEngine:
    from pwnproxy.shared.db import create_engine as make_traffic_engine
    return make_traffic_engine()


def _create_sessions_engine() -> AsyncEngine:
    db_path = Path.home() / ".pwnproxy" / "sessions.db"
    db_url = f"sqlite+aiosqlite:///{db_path.absolute()}"
    return create_async_engine(db_url, echo=False)


async def start_api_server(
    hook_bus: HookBus,
    bus=None,
    traffic_engine: Optional[AsyncEngine] = None,
    scanner_engine: Optional[AsyncEngine] = None,
    token_storage=None,
    interceptor_controller=None,
    repeater_engine=None,
    intruder_engine=None,
    session_manager=None,
    plugin_loader=None,
    proxy_engine=None,
    crawler_process=None,
    host: str = "127.0.0.1",
    port: int = 8000,
    proxy_port: int = 8080,
) -> asyncio.Task:
    """Start the FastAPI/Uvicorn server in a background task."""
    if traffic_engine is None:
        traffic_engine = _create_traffic_engine()
    if scanner_engine is None:
        scanner_engine = _create_scanner_engine()

    app.state.hook_bus = hook_bus
    app.state.bus = bus
    app.state.traffic_engine = traffic_engine
    app.state.scanner_engine = scanner_engine
    app.state.token_storage = token_storage
    app.state.interceptor_controller = interceptor_controller
    app.state.repeater_engine = repeater_engine
    app.state.intruder_engine = intruder_engine
    app.state.session_manager = session_manager
    app.state.plugin_loader = plugin_loader
    app.state.proxy_engine = proxy_engine or (session_manager.get_proxy_engine() if session_manager else None)
    app.state.crawler_process = crawler_process
    app.state.task_store = session_manager.task_store if session_manager else None
    app.state.proxy_port = proxy_port

    llm_ledger = UsageLedger(default_ledger_engine())
    app.state.llm_client = create_client_from_config(ledger=llm_ledger)

    # FP-triage pipeline: every persisted finding goes through it exactly once
    # (class-level hook covers all FindingStorage instances: API scan + plugin paths).
    from pwnproxy.ai.triage import TriagePipeline, load_triage_config
    from pwnproxy.ai.triage.judge import LLMJudge
    from pwnproxy.shared.findings.storage import FindingStorage

    def _triage_storage():
        engine = session_manager.get_scanner_engine() if session_manager else scanner_engine
        return FindingStorage(engine)

    triage_pipeline = TriagePipeline(
        _triage_storage,
        hook_bus=hook_bus,
        judge=LLMJudge(app.state.llm_client),
        config=load_triage_config(),
    )
    app.state.triage_pipeline = triage_pipeline
    FindingStorage.on_saved = triage_pipeline.handle
    triage_pipeline.start()

    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="info",
        access_log=False,
    )
    server = uvicorn.Server(config)

    async def _serve() -> None:
        try:
            await server.serve()
        except asyncio.CancelledError:
            pass

    task = asyncio.create_task(_serve())
    logger.info(f"API server started on {host}:{port}")
    return task
