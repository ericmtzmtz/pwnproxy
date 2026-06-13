import asyncio
import logging
import uuid
from typing import Optional

from aiohttp import web

logger = logging.getLogger(__name__)


class CallbackServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 18080):
        self._host = host
        self._port = port
        self._hits: dict[str, dict] = {}
        self._app: Optional[web.Application] = None
        self._runner: Optional[web.AppRunner] = None
        self._site: Optional[web.TCPSite] = None
        self._running = False

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        return self._port

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def hits(self) -> dict[str, dict]:
        return dict(self._hits)

    def pop_hit(self, canary: str) -> Optional[dict]:
        return self._hits.pop(canary, None)

    async def start(self) -> None:
        if self._running:
            return

        self._app = web.Application()
        self._app.router.add_route("*", "/callback/{canary}", self._handle_callback)

        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, self._host, self._port)
        await self._site.start()

        self._running = True
        logger.info(f"CallbackServer listening on {self._host}:{self._port}")

    async def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
        self._app = None
        logger.info("CallbackServer stopped")

    async def _handle_callback(self, request: web.Request) -> web.Response:
        canary = request.match_info.get("canary", "")
        peername = request.transport.get_extra_info("peername")
        hit = {
            "canary": canary,
            "remote_ip": peername[0] if peername else "unknown",
            "remote_port": peername[1] if peername else 0,
            "method": request.method,
            "path": str(request.url.path),
            "headers": dict(request.headers),
        }
        self._hits[canary] = hit
        logger.info(f"SSRF callback hit: canary={canary} from={hit['remote_ip']}")
        return web.json_response({"status": "received"})

    def generate_payload(self, canary: Optional[str] = None) -> str:
        if canary is None:
            canary = str(uuid.uuid4())
        return f"http://{self._host}:{self._port}/callback/{canary}"
