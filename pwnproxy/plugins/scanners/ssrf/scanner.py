import logging
from collections.abc import AsyncGenerator

from pwnproxy.plugins.core.base import Finding
from pwnproxy.plugins.core.chain import DetectionChain, DetectionDepth
from pwnproxy.shared.scan.stages.ssrf_stages import (
    SsrfSimpleStage,
    RedirectStage,
    SsrfOOBStage,
)
from pwnproxy.shared.scan.replayer import RequestReplayer
from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.shared.models import Flow

logger = logging.getLogger(__name__)


class SSRFScanner:
    def __init__(
        self,
        replayer: RequestReplayer,
        depth: str = "fast",
        evasion: str = "none",
        callback_host: str = "127.0.0.1",
        callback_port: int = 18080,
    ):
        self._replayer = replayer
        self._depth = depth
        self._evasion = evasion
        self._callback_host = callback_host
        self._callback_port = callback_port

    async def _scan_point(self, point: InjectionPoint) -> AsyncGenerator[Finding, None]:
        stages = [
            SsrfSimpleStage(
                self._replayer,
                callback_host=self._callback_host,
                callback_port=self._callback_port,
                evasion_level=self._evasion,
            ),
            RedirectStage(self._replayer, evasion_level=self._evasion),
            SsrfOOBStage(
                self._replayer,
                callback_host=self._callback_host,
                callback_port=self._callback_port,
                evasion_level=self._evasion,
            ),
        ]
        chain = DetectionChain(stages, DetectionDepth(self._depth))

        body_bytes = point.original_body.encode() if point.original_body else None
        flow = Flow(
            id=point.flow_id,
            method=point.method,
            url=point.url,
            request_headers=dict(point.original_headers),
            request_body=body_bytes,
        )

        async for finding in chain.run(flow, [point]):
            yield finding
