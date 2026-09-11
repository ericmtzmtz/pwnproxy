import asyncio
import contextlib
import logging
from collections.abc import Callable

from pwnproxy.services.session.extractors import cookies, csrf, jwt
from pwnproxy.services.session.models import TokenCandidate
from pwnproxy.services.session.storage import TokenStorage
from pwnproxy.services.session.validator import jwt_decode
from pwnproxy.shared.hooks import HookBus
from pwnproxy.shared.models import Flow

logger = logging.getLogger(__name__)


class SessionConsumer:
    def __init__(
        self,
        hook_bus: HookBus,
        storage: TokenStorage | None = None,
        on_token: Callable | None = None,
    ):
        self._hook_bus = hook_bus
        self._storage = storage or TokenStorage()
        self._on_token = on_token

        self._queue: asyncio.Queue | None = None
        self._task: asyncio.Task | None = None
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
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task
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
