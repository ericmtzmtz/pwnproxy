import logging
from typing import Optional

from pwnproxy.services.scan.params import InjectionPoint
from pwnproxy.services.scanners.lfi.signatures import detect_os
from pwnproxy.services.scanners.xxe.models import XxeFinding
from pwnproxy.services.scanners.xxe.payloads import (
    XxePayload,
    get_error_payloads,
    get_oob_payloads,
    get_xinclude_payloads,
)
from pwnproxy.services.scanners.xxe.replayer import XxeReplayer

logger = logging.getLogger(__name__)


class XxeDetector:
    def __init__(self, replayer: XxeReplayer):
        self._replayer = replayer

    async def check_error_based(self, point: InjectionPoint) -> Optional[XxeFinding]:
        for payload in get_error_payloads():
            result = await self._try_payload(point, payload)
            if result is not None:
                return result
        return None

    async def check_xinclude(self, point: InjectionPoint) -> Optional[XxeFinding]:
        for payload in get_xinclude_payloads():
            result = await self._try_payload(point, payload)
            if result is not None:
                return result
        return None

    async def _try_payload(self, point: InjectionPoint, payload: XxePayload) -> Optional[XxeFinding]:
        resp = await self._replayer.replay_raw_body(point, payload.value)
        if resp is None:
            return None

        body = resp.text or ""
        os_type, evidence = detect_os(body)
        if os_type is not None:
            mutation = "none"
            return self._make_finding(point, payload, os_type, mutation, "high", evidence)

        if resp.status_code in (500, 502, 503):
            if "XML" in body or "parser" in body.lower() or "entity" in body.lower():
                return self._make_finding(
                    point, payload, "unknown", "none", "medium", body[:300]
                )

        return None

    async def check_oob(
        self, point: InjectionPoint, oob_domain: str
    ) -> Optional[XxeFinding]:
        for payload in get_oob_payloads(oob_domain):
            resp = await self._replayer.replay_raw_body(point, payload.value)
            mutation = "none"
            finding = self._make_finding(
                point,
                payload,
                "unknown",
                mutation,
                "low",
                None,
                oob_domain=oob_domain,
                technique="oob",
            )
            return finding
        return None

    async def check_json_mutated(self, point: InjectionPoint) -> Optional[XxeFinding]:
        for payload in get_error_payloads():
            mutated = await self._replayer.replay_json_mutated(
                point,
                payload.value,
            )
            if mutated is None:
                continue

            body = mutated.text or ""
            os_type, evidence = detect_os(body)
            if os_type is not None:
                mutation = "json-to-xml"
                return self._make_finding(point, payload, os_type, mutation, "high", evidence)

        return None

    def _make_finding(
        self,
        point: InjectionPoint,
        payload: XxePayload,
        os_type: str,
        mutation: str,
        confidence: str,
        evidence: Optional[str] = None,
        oob_domain: Optional[str] = None,
        technique: Optional[str] = None,
    ) -> XxeFinding:
        return XxeFinding(
            url=point.url,
            param_name=point.name,
            param_location=point.location,
            technique=technique or payload.technique,
            payload=payload.value,
            evidence=evidence[:500] if evidence else None,
            mutation=mutation,
            oob_domain=oob_domain,
            severity="high" if confidence == "high" else "medium" if confidence == "medium" else "low",
            confidence=confidence,
        )
