import logging
from typing import Optional

import httpx

from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.shared.scan.replayer import RequestReplayer

logger = logging.getLogger(__name__)


class XssReplayer(RequestReplayer):
    async def replay(
        self,
        point: InjectionPoint,
        payload: str,
        timeout: float = 5.0,
        evasion_level: str | None = None,
    ) -> Optional[httpx.Response]:
        return await super().replay(point, payload, timeout=timeout, evasion_level=evasion_level or "none")
