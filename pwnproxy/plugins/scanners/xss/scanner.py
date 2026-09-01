import logging
from collections.abc import AsyncGenerator

from pwnproxy.plugins.core.base import Finding
from pwnproxy.plugins.core.chain import DetectionChain, DetectionDepth
from pwnproxy.shared.scan.stages.xss_stages import (
    ReflectedStage,
    StoredStage,
    DomStage,
    ContextAwareStage,
)
from pwnproxy.shared.scan.replayer import RequestReplayer
from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.shared.models import Flow

logger = logging.getLogger(__name__)


class XSSScanner:
    def __init__(
        self,
        replayer: RequestReplayer,
        depth: str = "fast",
        evasion: str = "none",
    ):
        self._replayer = replayer
        self._depth = depth
        self._evasion = evasion

    async def _scan_point(self, point: InjectionPoint) -> AsyncGenerator[Finding, None]:
        stages = [
            ReflectedStage(self._replayer, evasion_level=self._evasion),
            StoredStage(self._replayer, evasion_level=self._evasion),
            DomStage(self._replayer, evasion_level=self._evasion),
            ContextAwareStage(self._replayer, evasion_level=self._evasion),
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
