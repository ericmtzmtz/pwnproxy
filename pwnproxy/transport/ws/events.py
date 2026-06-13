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


class RoomManager:
    def __init__(self):
        self._rooms: Dict[str, Set[WebSocket]] = {}

    async def connect(self, room_id: str, ws: WebSocket) -> None:
        await ws.accept()
        if room_id not in self._rooms:
            self._rooms[room_id] = set()
        self._rooms[room_id].add(ws)

    def disconnect(self, room_id: str, ws: WebSocket) -> None:
        room = self._rooms.get(room_id)
        if room:
            room.discard(ws)
            if not room:
                del self._rooms[room_id]

    async def broadcast(self, room_id: str, message: str) -> None:
        room = self._rooms.get(room_id)
        if not room:
            return
        dead: List[WebSocket] = []
        for ws in room:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            room.discard(ws)
        if room and not room:
            del self._rooms[room_id]


traffic_manager = ConnectionManager()
findings_manager = ConnectionManager()
events_manager = ConnectionManager()
room_manager = RoomManager()

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
    hook_bus = ws.app.state.hook_bus
    finding_queue = hook_bus.register("finding")

    try:
        while True:
            finding_data = await finding_queue.get()
            payload = json.dumps({"type": "finding", **finding_data}, default=str)
            await ws.send_text(payload)
    except WebSocketDisconnect:
        findings_manager.disconnect(ws)
    except asyncio.CancelledError:
        pass


@router.websocket("/ws/events")
async def ws_events(ws: WebSocket):
    await events_manager.connect(ws)
    hook_bus = ws.app.state.hook_bus
    flow_queue = hook_bus.register("flow_stored")
    finding_queue = hook_bus.register("finding")

    try:
        while True:
            done, _ = await asyncio.wait(
                [asyncio.create_task(flow_queue.get()), asyncio.create_task(finding_queue.get())],
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in done:
                result = task.result()
                if isinstance(result, dict) and "scanner" in result:
                    payload = json.dumps({"type": "finding", **result}, default=str)
                elif isinstance(result, dict):
                    payload = json.dumps(
                        {
                            "type": "flow",
                            "id": result.get("id"),
                            "method": result.get("method", ""),
                            "url": result.get("url", ""),
                            "status_code": result.get("status_code"),
                        },
                        default=str,
                    )
                await ws.send_text(payload)
    except WebSocketDisconnect:
        events_manager.disconnect(ws)
    except asyncio.CancelledError:
        pass


@router.websocket("/ws/rooms/{room_id}")
async def ws_room(ws: WebSocket, room_id: str):
    await room_manager.connect(room_id, ws)
    hook_bus = ws.app.state.hook_bus
    queue = hook_bus.register("response")

    try:
        while True:
            flow = await queue.get()
            payload = json.dumps(
                {
                    "type": "flow",
                    "room": room_id,
                    "method": flow.method,
                    "url": flow.url,
                    "id": flow.id,
                    "status_code": flow.status_code,
                },
                default=str,
            )
            await ws.send_text(payload)
    except WebSocketDisconnect:
        room_manager.disconnect(room_id, ws)
    except asyncio.CancelledError:
        pass
