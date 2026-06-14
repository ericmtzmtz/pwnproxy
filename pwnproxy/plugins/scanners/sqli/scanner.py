import logging
from collections.abc import AsyncGenerator

from pwnproxy.shared.models import Flow
from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.plugins.core.chain import DetectionChain
from pwnproxy.plugins.core.base import Finding

logger = logging.getLogger(__name__)


class SQLiScanner:
    def __init__(self, chain: DetectionChain):
        self._chain = chain

    async def _scan_point(self, point: InjectionPoint) -> AsyncGenerator[Finding, None]:
        body_bytes = point.original_body.encode() if point.original_body else None
        flow = Flow(
            id=point.flow_id,
            method=point.method,
            url=point.url,
            request_headers=dict(point.original_headers),
            request_body=body_bytes,
        )

        async for finding in self._chain.run(flow, [point]):
            yield finding
