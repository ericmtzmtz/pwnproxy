import logging
from typing import Optional

import httpx

from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.shared.scan.replayer import RequestReplayer

logger = logging.getLogger(__name__)


class SsrfReplayer(RequestReplayer):
    async def inject(
        self,
        point: InjectionPoint,
        payload: str,
        evasion_level: str | None = None,
    ) -> Optional[httpx.Response]:
        return await super().replay(point, payload, timeout=5.0, evasion_level=evasion_level or "none")
