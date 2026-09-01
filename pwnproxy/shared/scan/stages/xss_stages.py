"""XSS detection stages for DetectionChain.

Stages
------
- ReflectedStage:       order=0, min_depth=fast     — canary probe + exploitability gate
- StoredStage:          order=1, min_depth=standard — payload persists across requests
- DomStage:             order=2, min_depth=standard — static DOM sink detection (inferred)
- ContextAwareStage:    order=3, min_depth=deep     — deep context payload sweep
"""

import logging
import re
import uuid

import httpx

from pwnproxy.plugins.core.base import Finding
from pwnproxy.plugins.core.chain import DetectionDepth, DetectionStage, StageResult
from pwnproxy.shared.models import Flow
from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.shared.scan.replayer import RequestReplayer, _serialize_request

logger = logging.getLogger(__name__)

STORED_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "{{constructor.constructor('alert(1)')()}}",
]


def _default_canary() -> str:
    """Per-scan unique canary so a single scan's reflections are traceable and
    not filterable by a fixed, hardcoded marker."""
    return f"pwnxss-{uuid.uuid4().hex[:12]}"


def _xss_context():
    """Lazily import the XSS context analyzer to avoid a circular import.

    ``xss_stages`` is imported by ``xss/scanner.py``, while this module needs
    the ``xss`` package submodules; importing them eagerly would run the
    package ``__init__`` and re-enter the scanner before this module finishes
    loading.
    """
    from pwnproxy.plugins.scanners.xss.context import ContextAnalyzer, ReflectionContext
    return ContextAnalyzer, ReflectionContext


def _xss_payloads():
    from pwnproxy.plugins.scanners.xss.payloads import get_payloads_for_context
    return get_payloads_for_context


def _reflect_contexts(analyzer, body: str, canary: str) -> list:
    """Reflection contexts of the canary, excluding UNKNOWN."""
    _, ReflectionContext = _xss_context()
    return [c for c in analyzer.analyze(body, canary) if c != ReflectionContext.UNKNOWN]


class ReflectedStage(DetectionStage):
    order = 0
    min_depth = DetectionDepth.FAST
    capability = "reflected-xss"

    def __init__(self, replayer: RequestReplayer, canary_provider=None, evasion_level: str = "none"):
        self._replayer = replayer
        self._evasion = evasion_level
        self._canary_provider = canary_provider or _default_canary

    async def execute(
        self,
        flow: Flow,
        injection_points: list[InjectionPoint],
    ) -> StageResult:
        findings: list[Finding] = []
        confirmed: set[tuple] = set()
        ContextAnalyzer, _ = _xss_context()
        get_payloads_for_context = _xss_payloads()
        analyzer = ContextAnalyzer()
        canary = self._canary_provider()

        for point in injection_points:
            probe = await self._replayer.replay(
                point,
                canary,
                timeout=5.0,
                evasion_level=self._evasion,
            )
            if probe is None:
                continue

            # Not reflected at all → no XSS signal, skip the point.
            if canary not in probe.text:
                continue

            contexts = _reflect_contexts(analyzer, probe.text, canary)
            exploitable_ctx = None
            exploitable_payload = None
            reason = None

            for ctx in contexts:
                for payload_obj in get_payloads_for_context(ctx.value):
                    injected = await self._replayer.replay(
                        point,
                        payload_obj.value,
                        timeout=5.0,
                        evasion_level=self._evasion,
                    )
                    if injected is None:
                        continue
                    exploitable, _, r = analyzer.is_exploitable(injected.text, payload_obj.value)
                    if exploitable:
                        exploitable_ctx = ctx
                        exploitable_payload = payload_obj.value
                        reason = r
                        break
                if exploitable_ctx is not None:
                    break

            if exploitable_ctx is not None:
                req = self._replayer.build_payload_request(
                    point, exploitable_payload, evasion_level=self._evasion
                )
                findings.append(Finding(
                    scanner="xss",
                    url=point.url,
                    method=point.method,
                    param_name=point.name,
                    param_location=point.location,
                    technique="reflected-xss",
                    severity="high",
                    confidence="confirmed",
                    payload=exploitable_payload,
                    evidence=f"Exploitable reflection in {exploitable_ctx.value}: {reason}",
                    extra={"context": exploitable_ctx.value, "reason": reason},
                    request_data=_serialize_request(req),
                ))
                confirmed.add(self._point_key(point))
            else:
                # Reflected but not exploitable → low-confidence signal, distinct
                # from XSS. Does NOT confirm the point (deep stage may still find
                # an exploitable payload), so it never collides with reflected-xss.
                req = self._replayer.build_payload_request(point, canary, evasion_level=self._evasion)
                findings.append(Finding(
                    scanner="xss",
                    url=point.url,
                    method=point.method,
                    param_name=point.name,
                    param_location=point.location,
                    technique="unescaped-reflection",
                    severity="low",
                    confidence="tentative",
                    payload=canary,
                    evidence="Canary reflected but no exploitable breakout found",
                    request_data=_serialize_request(req),
                ))

        return StageResult(findings=findings, confirmed_points=confirmed)

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


class DomStage(DetectionStage):
    """Static DOM-based XSS detection.

    Two signals, both ``confidence="inferred"`` (no JS execution):

    1. Canary-in-sink: the injected canary appears inside a recognized DOM
       sink in the served script (server reflects the value into JS).
    2. Param-reads-location: the script reads this parameter's NAME from
       ``location.*`` / URLSearchParams and the same block writes to a DOM
       sink — the classic DVWA xss_d pattern where the server does NOT
       reflect the injected value at all.

    If the canary IS in the HTML body, ReflectedStage owns it and this stage
    skips to avoid duplicates.
    """

    order = 2
    min_depth = DetectionDepth.FAST
    capability = "dom-xss"

    def __init__(self, replayer: RequestReplayer, canary_provider=None, evasion_level: str = "none"):
        self._replayer = replayer
        self._evasion = evasion_level
        self._canary_provider = canary_provider or _default_canary

    async def execute(
        self,
        flow: Flow,
        injection_points: list[InjectionPoint],
    ) -> StageResult:
        findings: list[Finding] = []
        confirmed: set[tuple] = set()
        canary = self._canary_provider()

        for point in injection_points:
            probe = await self._replayer.replay(
                point,
                canary,
                timeout=5.0,
                evasion_level=self._evasion,
            )
            if probe is None:
                continue

            body = probe.text or ""
            # ReflectedStage owns server-side reflection: if the canary appears
            # in the HTML OUTSIDE script blocks, skip (no DOM-only signal).
            if self._canary_in_html_body(body, canary):
                continue

            from pwnproxy.plugins.scanners.xss.dom_sinks import (
                find_sinks,
                find_sink_snippet,
                find_param_location_sinks,
                find_param_location_snippet,
            )

            # Signal 1: canary inside a sink in the served script.
            sink = None
            snippet = ""
            canary_sinks = find_sinks(body, canary)
            if canary_sinks:
                sink = canary_sinks[0]
                snippet = find_sink_snippet(body, canary, sink)
                evidence = f"Canary reaches DOM sink '{sink.name}' in served script"
            else:
                # Signal 2: script reads this param from location.* into a sink.
                param_sinks = find_param_location_sinks(body, point.name)
                if param_sinks:
                    sink = param_sinks[0]
                    snippet = find_param_location_snippet(body, point.name, sink)
                    evidence = (
                        f"Param '{point.name}' is read from location into a script "
                        f"writing to DOM sink '{sink.name}'"
                    )
            if sink is None:
                continue

            req = self._replayer.build_payload_request(point, canary, evasion_level=self._evasion)
            findings.append(Finding(
                scanner="xss",
                url=point.url,
                method=point.method,
                param_name=point.name,
                param_location=point.location,
                technique="dom-xss",
                severity="medium",
                confidence="inferred",
                payload=canary,
                evidence=evidence,
                extra={"dom_sink": sink.name, "snippet": snippet},
                request_data=_serialize_request(req),
            ))
            confirmed.add(self._point_key(point))

        return StageResult(findings=findings, confirmed_points=confirmed)

    @staticmethod
    def _canary_in_html_body(body: str, canary: str) -> bool:
        """True if the canary appears in the HTML outside of <script> blocks."""
        if canary not in body:
            return False
        stripped = re.sub(r"<script\b[^>]*>.*?</script>", "", body, flags=re.I | re.S)
        return canary in stripped

    @staticmethod
    def _point_key(point: InjectionPoint) -> tuple:
        return (point.method, point.host + point.path, point.name, point.location)


class ContextAwareStage(DetectionStage):
    order = 3
    min_depth = DetectionDepth.DEEP
    capability = "reflected-xss"

    def __init__(self, replayer: RequestReplayer, canary_provider=None, evasion_level: str = "none"):
        self._replayer = replayer
        self._evasion = evasion_level
        self._canary_provider = canary_provider or _default_canary

    async def execute(
        self,
        flow: Flow,
        injection_points: list[InjectionPoint],
    ) -> StageResult:
        findings: list[Finding] = []
        confirmed: set[tuple] = set()
        ContextAnalyzer, _ = _xss_context()
        get_payloads_for_context = _xss_payloads()
        analyzer = ContextAnalyzer()
        canary = self._canary_provider()

        for point in injection_points:
            probe = await self._replayer.replay(
                point,
                canary,
                timeout=5.0,
                evasion_level=self._evasion,
            )
            if probe is None:
                continue

            contexts = _reflect_contexts(analyzer, probe.text, canary)
            found = False
            for ctx in contexts:
                payloads = get_payloads_for_context(ctx.value)
                for payload_obj in payloads:
                    injected = await self._replayer.replay(
                        point,
                        payload_obj.value,
                        timeout=5.0,
                        evasion_level=self._evasion,
                    )
                    if injected is None:
                        continue
                    exploitable, _, reason = analyzer.is_exploitable(injected.text, payload_obj.value)
                    if exploitable:
                        req = self._replayer.build_payload_request(point, payload_obj.value, evasion_level=self._evasion)
                        findings.append(Finding(
                            scanner="xss",
                            url=point.url,
                            method=point.method,
                            param_name=point.name,
                            param_location=point.location,
                            technique="reflected-xss",
                            severity="high",
                            confidence="confirmed",
                            payload=payload_obj.value,
                            evidence=f"Context-aware exploitable reflection in {ctx.value}: {reason}",
                            extra={"context": ctx.value, "reason": reason},
                            request_data=_serialize_request(req),
                        ))
                        confirmed.add(self._point_key(point))
                        found = True
                        break
                if found:
                    break

        return StageResult(findings=findings, confirmed_points=confirmed)

    @staticmethod
    def _point_key(point: InjectionPoint) -> tuple:
        return (point.method, point.host + point.path, point.name, point.location)
