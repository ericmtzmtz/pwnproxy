import logging
from typing import Optional

import httpx

from pwnproxy.services.scan.params import InjectionPoint
from pwnproxy.services.scanners.xss.canary import CanaryMatch, CanaryStore
from pwnproxy.services.scanners.xss.context import ContextAnalyzer, ReflectionContext
from pwnproxy.services.scanners.xss.models import XssFinding
from pwnproxy.services.scanners.xss.payloads import (
    PROBE_PAYLOAD,
    get_payloads_for_context,
)
from pwnproxy.services.scanners.xss.replayer import XssReplayer

logger = logging.getLogger(__name__)

class ReflectedDetector:
    def __init__(self, replayer: XssReplayer, context_analyzer: Optional[ContextAnalyzer] = None):
        self._replayer = replayer
        self._context_analyzer = context_analyzer or ContextAnalyzer()

    async def check(self, point: InjectionPoint, canary_store: CanaryStore) -> Optional[XssFinding]:
        probe_resp = await self._replayer.replay(point, PROBE_PAYLOAD, timeout=5.0)
        if probe_resp is None:
            return None
        body = probe_resp.text or ""

        if PROBE_PAYLOAD not in body:
            return None

        canary = canary_store.generate()
        await canary_store.store(canary, point.url, point.name, point.location)

        canary_resp = await self._replayer.replay(point, canary, timeout=5.0)
        if canary_resp is None:
            return None
        canary_body = canary_resp.text or ""

        if canary not in canary_body:
            return None

        contexts = self._context_analyzer.analyze(canary_body, canary)
        for ctx in contexts:
            finding = await self._test_context_payloads(point, ctx, canary)
            if finding:
                return finding
        return None

    async def _test_context_payloads(self, point: InjectionPoint, context: ReflectionContext, canary: str) -> Optional[XssFinding]:
        payloads = get_payloads_for_context(context.value)
        for payload in payloads:
            resp = await self._replayer.replay(point, payload.value, timeout=5.0)
            if resp is None:
                continue
            body = resp.text or ""

            if self._is_escaped(body, payload.value):
                continue

            if payload.value in body:
                return self._make_finding(point, "reflected", context.value, payload.value, "high", "confirmed", body)
        return None

    def _is_escaped(self, body: str, payload: str) -> bool:
        if payload in body:
            return False
        encoded = (
            payload.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;")
        )
        if encoded != payload and encoded in body:
            return True
        return False

    def _make_finding(
        self, point: InjectionPoint, xss_type: str, context: str,
        payload: str, severity: str, confidence: str, body: str,
    ) -> XssFinding:
        evidence = body[:500] if body else None
        return XssFinding(
            method=point.method,
            url=point.url,
            param_name=point.name,
            param_location=point.location,
            xss_type=xss_type,
            context=context,
            severity=severity,
            confidence=confidence,
            payload=payload,
            evidence=evidence,
        )


class StoredDetector:
    def __init__(self, canary_store: CanaryStore):
        self._canary_store = canary_store

    async def check(self, body: str, response_url: str) -> list[XssFinding]:
        matches = await self._canary_store.scan_response(body, response_url)
        findings: list[XssFinding] = []
        for m in matches:
            findings.append(self._make_finding(m))
        return findings

    def _make_finding(self, match: CanaryMatch) -> XssFinding:
        return XssFinding(
            method="",
            url=match.source_url,
            param_name=match.param_name,
            param_location=match.param_location,
            xss_type="stored",
            context="html_body",
            severity="critical",
            confidence="confirmed",
            payload=match.canary_value,
            evidence=f"Canary {match.canary_value} injected at {match.source_url} reflected at {match.found_url}",
            reflection_url=match.found_url,
        )
