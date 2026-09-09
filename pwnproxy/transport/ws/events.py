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
        if not room:
            del self._rooms[room_id]


class RoomDispatcher:
    """Routes global HookBus events into per-session/job rooms.

    Started once at app lifespan, not per-connection. Subscribes to
    global channels, filters by ``session_id`` (and ``job_id`` for job
    rooms), and calls ``room_manager.broadcast(room_id, payload)``.
    Untagged events (no session_id) are NOT fanned out to session rooms.
    """

    # Global HookBus channels that carry session_id (or job_id)
    _CHANNELS = [
        "response",
        "flow",
        "done",
        "flow_stored",
        "finding",
        "triage.updated",
        "scan.started",
        "scan.completed",
        "autoscan.started",
        "autoscan.completed",
        "crawl.started",
        "crawl.progress",
        "crawl.completed",
        "crawl.failed",
        "bruteforce.started",
        "bruteforce.progress",
        "bruteforce.completed",
        "bruteforce.failed",
        "crawler.url",
    ]

    # Map HookBus channel -> room prefix
    _ROOM_PREFIX: Dict[str, str] = {
        "response": "traffic",
        "flow": "traffic",
        "done": "traffic",
        "flow_stored": "traffic",
        "finding": "findings",
        "triage.updated": "findings",
        "crawler.url": "traffic",
    }

    def __init__(self, hook_bus, room_mgr: RoomManager):
        self._hook_bus = hook_bus
        self._room_mgr = room_mgr
        self._tasks: List[asyncio.Task] = []
        self._running = False
        self._untagged: int = 0

    def _extract_session(self, data: Any) -> tuple[Optional[str], Optional[str]]:
        """Return (session_id, job_id) from event data (Flow or dict)."""
        session_id: Optional[str] = None
        job_id: Optional[str] = None
        if data is None:
            return None, None
        # Flow object (response/flow)
        if hasattr(data, "session_id"):
            try:
                session_id = getattr(data, "session_id")
            except Exception:
                session_id = None
            # Flow may also be the data itself; job_id not applicable
            return session_id, None
        if isinstance(data, dict):
            session_id = data.get("session_id")
            job_id = data.get("job_id") or data.get("task_id")
            # scan/crawl job_id may be int
            if job_id is not None:
                job_id = str(job_id)
        return session_id, job_id

    def _room_for(self, channel: str, session_id: Optional[str], job_id: Optional[str]) -> Optional[str]:
        if job_id and channel in ("crawl.started", "crawl.progress", "crawl.completed", "crawl.failed", "bruteforce.started", "bruteforce.progress", "bruteforce.completed", "bruteforce.failed", "scan.started", "scan.completed", "autoscan.started", "autoscan.completed"):
            return f"job:{job_id}"
        prefix = self._ROOM_PREFIX.get(channel)
        if prefix and session_id:
            return f"{prefix}:{session_id}"
        # Generic session channel fallback
        if channel.startswith("session:") and session_id:
            return f"session:{session_id}"
        return None

    async def _run_channel(self, channel: str) -> None:
        queue = self._hook_bus.register(channel)
        while self._running:
            try:
                data = await queue.get()
            except asyncio.CancelledError:
                break
            except Exception:
                continue
            session_id, job_id = self._extract_session(data)
            room_id = self._room_for(channel, session_id, job_id)
            if not room_id:
                if not session_id and not job_id:
                    self._untagged += 1
                    logger.debug("RoomDispatcher: untagged event on %s not fanned out", channel)
                continue
            # Build room envelope {type, session_id, data}
            try:
                if hasattr(data, "to_dict"):
                    payload_data = data.to_dict()
                elif hasattr(data, "__dict__") and not isinstance(data, dict):
                    payload_data = {"id": getattr(data, "id", None), "method": getattr(data, "method", None), "url": getattr(data, "url", None)}
                    # Include session_id already captured
                else:
                    payload_data = data
                envelope = json.dumps({"type": channel, "session_id": session_id, "job_id": job_id, "data": payload_data}, default=str)
            except Exception as exc:
                logger.debug("RoomDispatcher envelope failed for %s: %s", channel, exc)
                continue
            try:
                await self._room_mgr.broadcast(room_id, envelope)
            except Exception:
                pass

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        for channel in self._CHANNELS:
            try:
                task = asyncio.create_task(self._run_channel(channel))
                self._tasks.append(task)
            except Exception as exc:
                logger.warning("RoomDispatcher failed to subscribe %s: %s", channel, exc)

    async def stop(self) -> None:
        self._running = False
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()


traffic_manager = ConnectionManager()
findings_manager = ConnectionManager()
events_manager = ConnectionManager()
room_manager = RoomManager()
room_dispatcher = RoomDispatcher(None, room_manager)  # hook_bus injected at startup

FINDINGS_TABLE = "findings"


@router.websocket("/ws/traffic")
async def ws_traffic(ws: WebSocket):
    await traffic_manager.connect(ws)
    hook_bus = ws.app.state.hook_bus
    queue = hook_bus.register("response")

    try:
        while True:
            flow = await queue.get()
            payload_dict: dict = {
                "type": "flow",
                "method": flow.method,
                "url": flow.url,
                "id": flow.id,
                "status_code": flow.status_code,
            }
            sid = getattr(flow, "session_id", None)
            if sid:
                payload_dict["session_id"] = sid
            payload = json.dumps(payload_dict, default=str)
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
    scan_started_queue = hook_bus.register("scan.started")
    scan_completed_queue = hook_bus.register("scan.completed")
    autoscan_started_queue = hook_bus.register("autoscan.started")
    autoscan_completed_queue = hook_bus.register("autoscan.completed")
    triage_queue = hook_bus.register("triage.updated")
    crawler_queue = hook_bus.register("crawler.url")
    crawl_started_queue = hook_bus.register("crawl.started")
    crawl_progress_queue = hook_bus.register("crawl.progress")
    crawl_completed_queue = hook_bus.register("crawl.completed")
    crawl_failed_queue = hook_bus.register("crawl.failed")
    bruteforce_started_queue = hook_bus.register("bruteforce.started")
    bruteforce_progress_queue = hook_bus.register("bruteforce.progress")
    bruteforce_completed_queue = hook_bus.register("bruteforce.completed")
    bruteforce_failed_queue = hook_bus.register("bruteforce.failed")

    try:
        while True:
            # Create a separate task for each queue get operation
            flow_task = asyncio.create_task(flow_queue.get())
            finding_task = asyncio.create_task(finding_queue.get())
            started_task = asyncio.create_task(scan_started_queue.get())
            completed_task = asyncio.create_task(scan_completed_queue.get())
            autoscan_started_task = asyncio.create_task(autoscan_started_queue.get())
            autoscan_completed_task = asyncio.create_task(autoscan_completed_queue.get())
            triage_task = asyncio.create_task(triage_queue.get())
            crawler_task = asyncio.create_task(crawler_queue.get())
            crawl_started_task = asyncio.create_task(crawl_started_queue.get())
            crawl_progress_task = asyncio.create_task(crawl_progress_queue.get())
            crawl_completed_task = asyncio.create_task(crawl_completed_queue.get())
            crawl_failed_task = asyncio.create_task(crawl_failed_queue.get())
            bruteforce_started_task = asyncio.create_task(bruteforce_started_queue.get())
            bruteforce_progress_task = asyncio.create_task(bruteforce_progress_queue.get())
            bruteforce_completed_task = asyncio.create_task(bruteforce_completed_queue.get())
            bruteforce_failed_task = asyncio.create_task(bruteforce_failed_queue.get())

            done, pending = await asyncio.wait(
                [flow_task, finding_task, started_task, completed_task,
                 autoscan_started_task, autoscan_completed_task, triage_task,
                 crawler_task, crawl_started_task, crawl_progress_task,
                 crawl_completed_task, crawl_failed_task,
                 bruteforce_started_task, bruteforce_progress_task,
                 bruteforce_completed_task, bruteforce_failed_task],
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            for task in done:
                result = task.result()
                payload = None
                if task is flow_task:
                    if isinstance(result, dict):
                        flow_payload: dict = {
                            "type": "flow",
                            "id": result.get("id"),
                            "method": result.get("method", ""),
                            "url": result.get("url", ""),
                            "status_code": result.get("status_code"),
                        }
                        if result.get("session_id"):
                            flow_payload["session_id"] = result["session_id"]
                        payload = json.dumps(flow_payload, default=str)
                elif task is finding_task:
                    if isinstance(result, dict) and "scanner" in result:
                        payload = json.dumps({"type": "finding", **result}, default=str)
                elif task is started_task:
                    if isinstance(result, dict):
                        payload = json.dumps({"type": "scan.started", **result}, default=str)
                elif task is completed_task:
                    if isinstance(result, dict):
                        payload = json.dumps({"type": "scan.completed", **result}, default=str)
                elif task is autoscan_started_task:
                    if isinstance(result, dict):
                        payload = json.dumps({"type": "autoscan.started", **result}, default=str)
                elif task is autoscan_completed_task:
                    if isinstance(result, dict):
                        payload = json.dumps({"type": "autoscan.completed", **result}, default=str)
                elif task is triage_task:
                    if isinstance(result, dict):
                        payload = json.dumps({"type": "triage.updated", **result}, default=str)
                elif task is crawler_task:
                    if isinstance(result, dict):
                        payload = json.dumps({"type": "crawler.url", **result}, default=str)
                elif task is crawl_started_task:
                    if isinstance(result, dict):
                        payload = json.dumps({"type": "crawl.started", **result}, default=str)
                elif task is crawl_progress_task:
                    if isinstance(result, dict):
                        payload = json.dumps({"type": "crawl.progress", **result}, default=str)
                elif task is crawl_completed_task:
                    if isinstance(result, dict):
                        payload = json.dumps({"type": "crawl.completed", **result}, default=str)
                elif task is crawl_failed_task:
                    if isinstance(result, dict):
                        payload = json.dumps({"type": "crawl.failed", **result}, default=str)
                elif task is bruteforce_started_task:
                    if isinstance(result, dict):
                        payload = json.dumps({"type": "bruteforce.started", **result}, default=str)
                elif task is bruteforce_progress_task:
                    if isinstance(result, dict):
                        payload = json.dumps({"type": "bruteforce.progress", **result}, default=str)
                elif task is bruteforce_completed_task:
                    if isinstance(result, dict):
                        payload = json.dumps({"type": "bruteforce.completed", **result}, default=str)
                elif task is bruteforce_failed_task:
                    if isinstance(result, dict):
                        payload = json.dumps({"type": "bruteforce.failed", **result}, default=str)

                if payload:
                    await ws.send_text(payload)

    except WebSocketDisconnect:
        events_manager.disconnect(ws)
    except asyncio.CancelledError:
        pass


_VALID_ROOM_PREFIXES = {"session", "traffic", "findings", "job"}

def _is_valid_room_id(room_id: str) -> bool:
    if ":" not in room_id:
        return False
    prefix, sid = room_id.split(":", 1)
    if prefix not in _VALID_ROOM_PREFIXES:
        return False
    if not sid or not sid.strip():
        return False
    return True


@router.websocket("/ws/rooms/{room_id}")
async def ws_room(ws: WebSocket, room_id: str):
    # Validate scheme before joining — fail closed on 4404
    if not _is_valid_room_id(room_id):
        await ws.accept()
        await ws.close(code=4404)
        return
    # Validate session exists for session/traffic/findings rooms using the live
    # SessionManager instance (not the static disk list), and fail closed.
    if ":" in room_id:
        prefix, sid = room_id.split(":", 1)
        if prefix in ("session", "traffic", "findings"):
            sm = getattr(ws.app.state, "session_manager", None)
            if sm is None:
                await ws.accept()
                await ws.close(code=4403)
                return
            try:
                # Prefer the live manager's active_name + list() for known sessions
                known = {s["name"] for s in sm.list()}
                # Also accept the active session even if not yet flushed to disk
                if sm.active_name:
                    known.add(sm.active_name)
                if sid not in known:
                    await ws.accept()
                    await ws.close(code=4403)
                    return
            except Exception:
                await ws.accept()
                await ws.close(code=4403)
                return
    await room_manager.connect(room_id, ws)
    try:
        while True:
            # Room is push-only via RoomDispatcher.broadcast; keep the socket
            # alive with a 30s receive timeout so we can send pings and detect
            # half-open connections. Most clients are read-only listeners.
            try:
                await asyncio.wait_for(ws.receive_text(), timeout=30.0)
            except asyncio.TimeoutError:
                try:
                    await ws.send_text('{"type":"ping"}')
                except Exception:
                    break
    except WebSocketDisconnect:
        room_manager.disconnect(room_id, ws)
    except asyncio.CancelledError:
        room_manager.disconnect(room_id, ws)
        pass