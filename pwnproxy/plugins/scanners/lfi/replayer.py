import logging
from typing import Optional

import httpx

from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.shared.scan.replayer import RequestReplayer

logger = logging.getLogger(__name__)

METHODS = ["GET", "POST", "OPTIONS", "PUT", "DELETE"]


class LfiReplayer(RequestReplayer):
    async def replay(
        self,
        point: InjectionPoint,
        payload: str,
        method: str = "",
        evasion_level: str | None = None,
    ) -> Optional[httpx.Response]:
        original_method = point.method
        if method:
            point.method = method
        try:
            return await super().replay(point, payload, timeout=5.0, evasion_level=evasion_level or "none")
        finally:
            point.method = original_method

    async def replay_methods(self, point: InjectionPoint, payload: str) -> list[tuple[str, httpx.Response]]:
        results: list[tuple[str, httpx.Response]] = []
        for method in METHODS:
            resp = await self.replay(point, payload, method=method)
            if resp is not None:
                results.append((method, resp))
        return results
