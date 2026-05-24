import asyncio
import logging
from typing import Callable, Optional

from pwnproxy.core.hooks import HookBus
from pwnproxy.core.models import Flow
from pwnproxy.modules.session_manager.extractors import cookies, csrf, jwt
from pwnproxy.modules.session_manager.models import TokenCandidate
from pwnproxy.modules.session_manager.storage import TokenStorage
from pwnproxy.modules.session_manager.validator import jwt_decode

logger = logging.getLogger(__name__)


class SessionConsumer:
    def __init__(
        self,
        hook_bus: HookBus,
        storage: Optional[TokenStorage] = None,
        on_token: Optional[Callable] = None,
    ):
        self._hook_bus = hook_bus
        self._storage = storage or TokenStorage()
        self._on_token = on_token

        self._queue: Optional[asyncio.Queue] = None
        self._task: Optional[asyncio.Task] = None
        self._running = False

    @property
    def storage(self) -> TokenStorage:
        return self._storage

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        await self._storage.init()
        self._queue = self._hook_bus.register("response")
        self._task = asyncio.create_task(self._consume_loop())

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None
        await self._storage.close()

    async def _consume_loop(self) -> None:
        while self._running:
            try:
                flow: Flow = await self._queue.get()
                candidates: list[TokenCandidate] = []
                candidates.extend(jwt.extract(flow))
                candidates.extend(cookies.extract(flow))
                candidates.extend(csrf.extract(flow))

                for c in candidates:
                    if c.token_type == "jwt":
                        decoded = jwt_decode(c.token_value)
                        c.decoded_header = decoded.get("header")
                        c.decoded_payload = decoded.get("payload")
                        c.status = decoded.get("status", "unknown")
                        c.expires_at = decoded.get("expires_at")

                if candidates:
                    await self._storage.save(candidates)
                    if self._on_token:
                        for c in candidates:
                            self._on_token(c)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Session consumer error: {e}", exc_info=True)
