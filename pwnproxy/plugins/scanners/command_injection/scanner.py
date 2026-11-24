from collections.abc import AsyncGenerator

from pwnproxy.plugins.core.base import Finding
from pwnproxy.plugins.core.chain import DetectionChain, DetectionDepth
from pwnproxy.plugins.scanners.command_injection.payloads import (
    COMMAND_PAYLOADS,
    WINDOWS_PAYLOADS,
)
from pwnproxy.plugins.scanners.command_injection.signatures import (
    get_evidence,
    has_command_output,
)
from pwnproxy.shared.models import Flow
from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.shared.scan.replayer import RequestReplayer
from pwnproxy.shared.scan.stages.command_injection_stages import CommandInjectionStage


class CommandInjectionScanner:
    """Scanner for OS command injection vulnerabilities."""

    def __init__(self, replayer: RequestReplayer, depth="fast", evasion="none"):
        payloads = COMMAND_PAYLOADS + WINDOWS_PAYLOADS
        self._chain = DetectionChain([
            CommandInjectionStage(
                replayer, payloads, has_command_output, get_evidence, evasion,
            ),
        ], DetectionDepth(depth))

    async def _scan_point(
        self, point: InjectionPoint, source: Flow | None = None
    ) -> AsyncGenerator[Finding, None]:
        """Run the chain for one injection point.

        Args:
            point: Injection point to test.
            source: Flow the point was extracted from. Its captured response
                (status, headers, body) travels with the synthetic per-point
                flow so the stage can skip binary responses without an extra
                request and use the captured body as the detection baseline.
                Omitting it keeps the old behaviour: no captured response, so
                the stage sends one clean request per point.

        Yields:
            Findings produced by the detection chain.
        """
        flow = Flow(
            id=point.flow_id,
            method=point.method,
            url=point.url,
            request_headers=point.original_headers,
            request_body=point.original_body,
            status_code=source.status_code if source is not None else None,
            response_headers=source.response_headers if source is not None else None,
            response_body=source.response_body if source is not None else None,
            response_body_truncated=(
                source.response_body_truncated if source is not None else False
            ),
        )
        async for finding in self._chain.run(flow, [point]):
            yield finding
