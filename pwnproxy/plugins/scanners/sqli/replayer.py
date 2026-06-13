import logging
from typing import Optional

import httpx

from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.shared.scan.replayer import RequestReplayer

logger = logging.getLogger(__name__)


class SQLiReplayer(RequestReplayer):
    async def replay(
        self,
        point: InjectionPoint,
        payload: str,
        timeout: float = 3.0,
        evasion_level: str | None = None,
    ) -> Optional[httpx.Response]:
        return await super().replay(point, payload, timeout=timeout, evasion_level=evasion_level or "none")

    async def send_clean(self, point: InjectionPoint, timeout: float = 10.0) -> Optional[httpx.Response]:
        return await super().send_clean(point, timeout=timeout)
