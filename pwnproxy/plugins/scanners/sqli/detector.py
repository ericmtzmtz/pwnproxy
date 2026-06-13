import logging
import re
import time
from typing import Optional

import httpx

from pwnproxy.plugins.scanners.sqli.models import ScanFinding
from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.plugins.scanners.sqli.payloads import Payload
from pwnproxy.plugins.scanners.sqli.replayer import RequestReplayer

logger = logging.getLogger(__name__)

ERROR_SIGNATURES: dict[str, list[re.Pattern]] = {
    "mysql": [
        re.compile(r"you have an error in your sql syntax", re.I),
        re.compile(r"warning: mysql", re.I),
        re.compile(r"mysql_fetch", re.I),
        re.compile(r"mysql_num_rows", re.I),
        re.compile(r"mysql_result", re.I),
        # removed: overlaps with mssql pattern
        re.compile(r"unknown column", re.I),
    ],
    "postgresql": [
        re.compile(r"error:\s+syntax error at or near", re.I),
        re.compile(r"pg_query\(\):", re.I),
        re.compile(r"pg_exec\(\):", re.I),
        re.compile(r"invalid input syntax for type", re.I),
        re.compile(r"column\s+\S+\s+does not exist", re.I),
        re.compile(r"relation\s+\S+\s+does not exist", re.I),
    ],
    "mssql": [
        re.compile(r"unclosed quotation mark after the character string", re.I),
        re.compile(r"microsoft ole db", re.I),
        re.compile(r"microsoft sql native client", re.I),
        re.compile(r"incorrect syntax near", re.I),
        re.compile(r"line \d+:", re.I),
        re.compile(r"conversion failed when converting", re.I),
    ],
    "sqlite": [
        re.compile(r'near\s+".*"\s*:\s*syntax error', re.I),
        re.compile(r"sqlite_error", re.I),
        re.compile(r"sql logic error", re.I),
        re.compile(r"no such table", re.I),
        re.compile(r"no such column", re.I),
    ],
    "oracle": [
        re.compile(r"ora-\d{5}", re.I),
        re.compile(r"oracle error", re.I),
        re.compile(r"pl/sql:", re.I),
        re.compile(r"ora-\d{4}", re.I),
    ],
}


class ErrorBasedDetector:
    def check(self, response: httpx.Response) -> Optional[ScanFinding]:
        body = response.text
        for dbms, patterns in ERROR_SIGNATURES.items():
            for pat in patterns:
                m = pat.search(body)
                if m:
                    finding = ScanFinding(
                        method="",
                        url="",
                        param_name="",
                        param_location="",
                        technique="error-based",
                        dbms=dbms,
                        severity="high",
                        confidence="confirmed",
                        payload="",
                        evidence=m.group()[:500],
                    )
                    return finding
        return None


class TimeBasedDetector:
    def __init__(self, replayer: RequestReplayer):
        self._replayer = replayer

    async def check(
        self, point: InjectionPoint, baseline_ms: float,
    ) -> Optional[ScanFinding]:
        for payload in self._get_primary_payloads():
            start = time.monotonic()
            resp = await self._replayer.replay(point, payload.value, timeout=15.0)
            elapsed = (time.monotonic() - start) * 1000
            if resp is None:
                continue
            if elapsed > baseline_ms + 4000:
                return await self._confirm(point, baseline_ms, payload, elapsed)
        return None

    async def _confirm(
        self, point: InjectionPoint, baseline_ms: float,
        primary_payload: Payload, primary_ms: float,
    ) -> ScanFinding:
        for payload in self._get_confirm_payloads(primary_payload.dbms):
            start = time.monotonic()
            resp = await self._replayer.replay(point, payload.value, timeout=15.0)
            elapsed = (time.monotonic() - start) * 1000
            if resp is None:
                return ScanFinding(
                    method=point.method, url=point.url,
                    param_name=point.name, param_location=point.location,
                    technique="time-based-blind",
                    dbms=primary_payload.dbms,
                    severity="medium", confidence="tentative",
                    payload=primary_payload.value,
                    evidence=f"Primary delay detected ({primary_ms:.0f}ms vs baseline {baseline_ms:.0f}ms) but confirmation failed",
                    baseline_ms=baseline_ms, response_ms=primary_ms,
                )
            if elapsed > baseline_ms + 2400:
                return ScanFinding(
                    method=point.method, url=point.url,
                    param_name=point.name, param_location=point.location,
                    technique="time-based-blind",
                    dbms=primary_payload.dbms,
                    severity="high", confidence="confirmed",
                    payload=primary_payload.value,
                    evidence=f"Delay confirmed: baseline={baseline_ms:.0f}ms, primary={primary_ms:.0f}ms, confirm={elapsed:.0f}ms",
                    baseline_ms=baseline_ms, response_ms=primary_ms,
                )
        return ScanFinding(
            method=point.method, url=point.url,
            param_name=point.name, param_location=point.location,
            technique="time-based-blind",
            dbms=primary_payload.dbms,
            severity="medium", confidence="tentative",
            payload=primary_payload.value,
            evidence=f"Primary delay ({primary_ms:.0f}ms) but confirmation below threshold",
            baseline_ms=baseline_ms, response_ms=primary_ms,
        )

    def _get_primary_payloads(self) -> list[Payload]:
        from pwnproxy.plugins.scanners.sqli.payloads import TIME_PAYLOADS
        seen = set()
        uniq = []
        for p in TIME_PAYLOADS:
            if p.dbms not in seen:
                seen.add(p.dbms)
                uniq.append(p)
        return uniq

    def _get_confirm_payloads(self, dbms: Optional[str]) -> list[Payload]:
        from pwnproxy.plugins.scanners.sqli.payloads import TIME_PAYLOADS
        return [p for p in TIME_PAYLOADS if p.dbms == dbms and "3" in p.value]
