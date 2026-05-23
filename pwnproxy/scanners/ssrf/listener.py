import asyncio
import json
import logging
import uuid
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request

logger = logging.getLogger(__name__)


class CallbackServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 8080):
        self._host = host
        self._port = port
        self._hits: dict[str, dict] = {}
        self._app: Optional[FastAPI] = None
        self._server: Optional[asyncio.Task] = None
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

    def _build_app(self) -> FastAPI:
        hits = self._hits

        @asynccontextmanager
        async def lifespan(app: FastAPI):
            self._running = True
            logger.info(f"CallbackServer listening on {self._host}:{self._port}")
            yield
            self._running = False
            logger.info("CallbackServer stopped")

        app = FastAPI(lifespan=lifespan)

        @app.api_route("/callback/{canary}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
        async def callback(canary: str, request: Request):
            hit = {
                "canary": canary,
                "remote_ip": request.client.host if request.client else "unknown",
                "remote_port": request.client.port if request.client else 0,
                "method": request.method,
                "path": str(request.url.path),
                "headers": dict(request.headers),
            }
            hits[canary] = hit
            logger.info(f"SSRF callback hit: canary={canary} from={hit['remote_ip']}")
            return {"status": "received"}

        return app

    async def start(self) -> None:
        if self._running:
            return
        import uvicorn
        config = uvicorn.Config(
            self._build_app(),
            host=self._host,
            port=self._port,
            log_level="warning",
            access_log=False,
        )
        server = uvicorn.Server(config)
        self._server = asyncio.create_task(server.serve())
        self._running = True

    async def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if self._server:
            self._server.cancel()
            try:
                await self._server
            except (asyncio.CancelledError, Exception):
                pass
            self._server = None

    def generate_payload(self, canary: Optional[str] = None) -> str:
        if canary is None:
            canary = str(uuid.uuid4())
        return f"http://{self._host}:{self._port}/callback/{canary}"
