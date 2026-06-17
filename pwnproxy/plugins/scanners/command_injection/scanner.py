from collections.abc import AsyncGenerator

from pwnproxy.plugins.core.base import Finding
from pwnproxy.plugins.core.chain import DetectionChain, DetectionDepth
from pwnproxy.shared.scan.stages.command_injection_stages import CommandInjectionStage
from pwnproxy.shared.scan.replayer import RequestReplayer
from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.shared.models import Flow
from pwnproxy.plugins.scanners.command_injection.payloads import COMMAND_PAYLOADS, WINDOWS_PAYLOADS


class CommandInjectionScanner:
    """Scanner for OS command injection vulnerabilities."""
    
    def __init__(self, replayer: RequestReplayer, depth="fast", evasion="none"):
        payloads = COMMAND_PAYLOADS + WINDOWS_PAYLOADS
        self._chain = DetectionChain([
            CommandInjectionStage(replayer, payloads, evasion),
        ], DetectionDepth(depth))
    
    async def _scan_point(self, point: InjectionPoint) -> AsyncGenerator[Finding, None]:
        flow = Flow(
            id=point.flow_id,
            method=point.method,
            url=point.url,
            request_headers=point.original_headers,
            request_body=point.original_body,
        )
        async for finding in self._chain.run(flow, [point]):
            yield finding
