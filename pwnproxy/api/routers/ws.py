import asyncio
import json
import logging
from typing import Any, Dict, List, Set

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

logger = logging.getLogger(__name__)

router = APIRouter(tags=["websocket"])


class ConnectionManager:
    def __init__(self):
        self._connections: Set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self._connections.discard(ws)

    async def broadcast(self, message: str) -> None:
        dead: List[WebSocket] = []
        for ws in self._connections:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._connections.discard(ws)

    @property
    def count(self) -> int:
        return len(self._connections)


traffic_manager = ConnectionManager()
findings_manager = ConnectionManager()

SCANNER_TABLES: Dict[str, str] = {
    "sqli": "scan_findings",
    "xss": "xss_findings",
    "lfi": "lfi_findings",
    "xxe": "xxe_findings",
    "ssrf": "ssrf_findings",
}


@router.websocket("/ws/traffic")
async def ws_traffic(ws: WebSocket):
    await traffic_manager.connect(ws)
    hook_bus = ws.app.state.hook_bus
    queue = hook_bus.register("response")

    try:
        while True:
            flow = await queue.get()
            payload = json.dumps(
                {
                    "type": "flow",
                    "method": flow.method,
                    "url": flow.url,
                    "id": flow.id,
                    "status_code": flow.status_code,
                },
                default=str,
            )
            await ws.send_text(payload)
    except WebSocketDisconnect:
        traffic_manager.disconnect(ws)
    except asyncio.CancelledError:
        pass


@router.websocket("/ws/findings")
async def ws_findings(ws: WebSocket):
    await findings_manager.connect(ws)
    engine = ws.app.state.scanner_engine
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    last_ids: Dict[str, int] = {name: 0 for name in SCANNER_TABLES}

    try:
        while True:
            await asyncio.sleep(1.0)

            async with factory() as session:
                for scanner_name, table in SCANNER_TABLES.items():
                    try:
                        result = await session.execute(
                            text(
                                f"SELECT * FROM {table} WHERE id > :last_id ORDER BY id ASC"
                            ),
                            {"last_id": last_ids[scanner_name]},
                        )
                        rows = result.mappings().all()
                        for row in rows:
                            item = dict(row)
                            item["scanner"] = scanner_name
                            last_ids[scanner_name] = max(
                                last_ids[scanner_name], item.get("id", 0)
                            )
                            await ws.send_text(
                                json.dumps(
                                    {"type": "finding", "scanner": scanner_name, **item},
                                    default=str,
                                )
                            )
                    except Exception as exc:
                        logger.debug(f"WS findings poll error for {table}: {exc}")
    except WebSocketDisconnect:
        findings_manager.disconnect(ws)
    except asyncio.CancelledError:
        pass
