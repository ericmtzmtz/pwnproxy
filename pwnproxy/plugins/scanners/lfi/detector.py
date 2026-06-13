import logging
from typing import Optional

from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.plugins.scanners.lfi.models import LfiFinding
from pwnproxy.plugins.scanners.lfi.payloads import LfiPayload, get_payloads
from pwnproxy.plugins.scanners.lfi.replayer import LfiReplayer
from pwnproxy.plugins.scanners.lfi.signatures import detect_os

logger = logging.getLogger(__name__)


class LfiDetector:
    def __init__(self, replayer: LfiReplayer):
        self._replayer = replayer

    async def check(self, point: InjectionPoint) -> Optional[LfiFinding]:
        for payload in get_payloads():
            finding = await self._try_payload(point, payload)
            if finding is not None:
                return finding
        return None

    async def _try_payload(self, point: InjectionPoint, payload: LfiPayload) -> Optional[LfiFinding]:
        results = await self._replayer.replay_methods(point, payload.value)
        for method, resp in results:
            body = resp.text or ""
            # Require at least 2 distinct signatures for confirmation
            os_type, evidence = detect_os(body, min_matches=2)
            if os_type is not None:
                return self._make_finding(point, method, payload, os_type, evidence)
        return None

    def _make_finding(
        self, point: InjectionPoint, successful_method: str,
        payload: LfiPayload, os_type: str, evidence: str,
    ) -> LfiFinding:
        return LfiFinding(
            original_method=point.method,
            successful_method=successful_method,
            url=point.url,
            param_name=point.name,
            param_location=point.location,
            payload=payload.value,
            evidence=evidence[:500],
            os=os_type,
            severity="high",
        )
