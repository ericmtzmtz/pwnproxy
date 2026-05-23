import asyncio
import time
from typing import Optional


class RateLimiter:
    def __init__(self, global_max: int = 5, per_host_max: int = 2, inter_req_delay: float = 0.1):
        self._global_sem = asyncio.Semaphore(global_max)
        self._per_host_max = per_host_max
        self._inter_req_delay = inter_req_delay
        self._host_sems: dict[str, asyncio.Semaphore] = {}
        self._host_last_req: dict[str, float] = {}
        self._host_lock = asyncio.Lock()

    async def acquire(self, host: str) -> None:
        await self._global_sem.acquire()

    async def release(self, host: str) -> None:
        self._global_sem.release()

    async def rate_limit(self, host: str) -> None:
        async with self._host_lock:
            if host not in self._host_sems:
                self._host_sems[host] = asyncio.Semaphore(self._per_host_max)
        async with self._host_sems[host]:
            async with self._host_lock:
                last = self._host_last_req.get(host, 0.0)
                now = time.monotonic()
                wait = self._inter_req_delay - (now - last)
                if wait > 0:
                    await asyncio.sleep(wait)
                self._host_last_req[host] = time.monotonic()
