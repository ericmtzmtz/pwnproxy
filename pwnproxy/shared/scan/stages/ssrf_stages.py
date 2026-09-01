"""SSRF detection stages for DetectionChain.

SimpleStage: Detect SSRF via error-based or content hints (treats any successful request as potential SSRF).
RedirectStage: Detect SSRF via redirect responses (3xx) indicating the server fetched the URL.
SsrfOOBStage: Out-of-Band SSRF detection via callback canary.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from pwnproxy.plugins.core.base import Finding
from pwnproxy.plugins.core.chain import DetectionDepth, DetectionStage, StageResult
from pwnproxy.shared.models import Flow
from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.shared.scan.replayer import RequestReplayer, _serialize_request
from pwnproxy.shared.canary import get_registry
from pwnproxy.shared.http_server import get_server

logger = logging.getLogger(__name__)


def _point_key(point: InjectionPoint) -> tuple:
    return (point.method, point.host + point.path, point.name, point.location)


async def _live_callback(server) -> tuple[str, int] | None:
    """Return (host, port) of the running OOB callback server, or None.

    Used by SSRF stages so probes hit the real OOB listener; fail-closed when
    the callback server is not running (no server → no SSRF confirmation).
    """
    try:
        if server is not None and server.is_running:
            return server.host, server.port
    except Exception:
        pass
    return None


class SsrfSimpleStage(DetectionStage):
    """SSRF detection via OOB callback confirmation.

    Injects a unique callback URL into the parameter and only reports SSRF
    when the OOB callback server receives a request for that canary — an HTTP
    response with any status code is NOT, by itself, evidence of SSRF.
    """

    order = 0
    min_depth = DetectionDepth.FAST
    capability = "ssrf-simple"

    def __init__(self, replayer: RequestReplayer, callback_host: str = "127.0.0.1", callback_port: int = 18080, evasion_level: str = "none"):
        self._replayer = replayer
        self._callback_host = callback_host
        self._callback_port = callback_port
        self._evasion = evasion_level

    async def execute(self, flow: Flow, injection_points: list[InjectionPoint]) -> StageResult:
        findings: list[Finding] = []
        confirmed: set[tuple] = set()

        server = await get_server()
        live = await _live_callback(server)
        if live is None:
            logger.debug("SsrfSimpleStage: callback server not running, fail-closed")
            return StageResult(findings=findings, confirmed_points=confirmed)

        registry = get_registry()

        for point in injection_points:
            canary = registry.create(f"ssrf-simple-{flow.id}-{point.name}")
            callback_url = server.get_callback_url(canary.token)

            from pwnproxy.shared.scan.params import InjectionPoint as IP
            probe_point = IP(
                flow_id=point.flow_id,
                method=point.method,
                url=point.url,
                host=point.host,
                path=point.path,
                name=point.name,
                location=point.location,
                value=callback_url,
                original_headers=point.original_headers,
                original_body=point.original_body,
            )
            resp = await self._replayer.replay(probe_point, callback_url, timeout=10.0, evasion_level=self._evasion)
            if resp is None:
                registry.cleanup_expired()
                continue

            import asyncio
            await asyncio.sleep(2)

            hit = registry.get(canary.token)
            if hit and hit.callback_received:
                req = self._replayer.build_payload_request(probe_point, callback_url, evasion_level=self._evasion)
                findings.append(Finding(
                    scanner="ssrf",
                    url=point.url,
                    method=point.method,
                    param_name=point.name,
                    param_location=point.location,
                    technique="ssrf-oob",
                    severity="high",
                    confidence="confirmed",
                    payload=callback_url,
                    evidence=f"OOB callback received from {hit.callback_ip}",
                    extra={"oob_token": canary.token},
                    request_data=_serialize_request(req),
                ))
                confirmed.add(_point_key(point))

            registry.cleanup_expired()

        return StageResult(findings=findings, confirmed_points=confirmed)


class RedirectStage(DetectionStage):
    """SSRF detection via redirect responses."""

    order = 1
    min_depth = DetectionDepth.FAST
    capability = "ssrf-redirect"

    def __init__(self, replayer: RequestReplayer, evasion_level: str = "none"):
        self._replayer = replayer
        self._evasion = evasion_level

    async def execute(self, flow: Flow, injection_points: list[InjectionPoint]) -> StageResult:
        findings: list[Finding] = []
        confirmed: set[tuple] = set()

        for point in injection_points:
            # Use a probe that would cause a redirect if the server is fetching URLs
            probe_url = f"http://{point.host}:{point.path}/redirect?target=http://127.0.0.1:9999/"
            from pwnproxy.shared.scan.params import InjectionPoint as IP
            probe_point = IP(
                flow_id=point.flow_id,
                method=point.method,
                url=point.url,
                host=point.host,
                path=point.path,
                name=point.name,
                location=point.location,
                value=probe_url,
                original_headers=point.original_headers,
                original_body=point.original_body,
            )
            resp = await self._replayer.replay(probe_point, probe_url, timeout=10.0, evasion_level=self._evasion)
            if resp is None:
                continue
            # If response is a redirect (3xx) and Location header points to our probe, consider SSRF
            if 300 <= resp.status_code < 400:
                location = resp.headers.get("location", "")
                if "127.0.0.1:9999" in location:
                    req = self._replayer.build_payload_request(probe_point, probe_url, evasion_level=self._evasion)
                    findings.append(Finding(
                        scanner="ssrf",
                        url=point.url,
                        method=point.method,
                        param_name=point.name,
                        param_location=point.location,
                        technique="ssrf-redirect",
                        severity="medium",
                        confidence="tentative",
                        payload=probe_url,
                        evidence=f"Redirect to {location}",
                        request_data=_serialize_request(req),
                    ))
                    confirmed.add(_point_key(point))
                    break

        return StageResult(findings=findings, confirmed_points=confirmed)


class SsrfOOBStage(DetectionStage):
    """Out-of-Band SSRF detection via callback canary."""

    order = 2
    min_depth = DetectionDepth.DEEP
    capability = "ssrf-oob"

    def __init__(self, replayer: RequestReplayer, callback_host: str = "127.0.0.1", callback_port: int = 18080, evasion_level: str = "none"):
        self._replayer = replayer
        self._callback_host = callback_host
        self._callback_port = callback_port
        self._evasion = evasion_level

    async def execute(self, flow: Flow, injection_points: list[InjectionPoint]) -> StageResult:
        findings: list[Finding] = []
        confirmed: set[tuple] = set()

        registry = get_registry()
        # Ensure callback server is running
        server = await get_server()

        for point in injection_points:
            scan_id = f"ssrf-oob-{flow.id}-{point.name}"
            canary = registry.create(scan_id)
            callback_url = server.get_callback_url(canary.token)
            # Inject callback URL as parameter value
            from pwnproxy.shared.scan.params import InjectionPoint as IP
            oob_point = IP(
                flow_id=point.flow_id,
                method=point.method,
                url=point.url,
                host=point.host,
                path=point.path,
                name=point.name,
                location=point.location,
                value=callback_url,
                original_headers=point.original_headers,
                original_body=point.original_body,
            )
            resp = await self._replayer.replay(oob_point, callback_url, timeout=15.0, evasion_level=self._evasion)
            if resp is None:
                continue

            # Wait a bit for callback
            import asyncio
            await asyncio.sleep(2)

            hit = registry.get(canary.token)
            if hit and hit.callback_received:
                req = self._replayer.build_payload_request(oob_point, callback_url, evasion_level=self._evasion)
                findings.append(Finding(
                    scanner="ssrf",
                    url=point.url,
                    method=point.method,
                    param_name=point.name,
                    param_location=point.location,
                    technique="ssrf-oob",
                    severity="high",
                    confidence="confirmed",
                    payload=callback_url,
                    evidence=f"OOB callback received from {hit.callback_ip}",
                    extra={"oob_token": canary.token},
                    request_data=_serialize_request(req),
                ))
                confirmed.add(_point_key(point))

            # Cleanup expired canaries occasionally
            registry.cleanup_expired()

        return StageResult(findings=findings, confirmed_points=confirmed)