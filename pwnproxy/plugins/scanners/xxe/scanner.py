"""XXE scanner using DetectionChain with XxeReplayer.

Orchestrates XXE detection stages (ErrorBased, JSONMutate, OOB)
via the shared DetectionChain framework and XxeReplayer for XML mutation.
"""

from __future__ import annotations

import logging

from pwnproxy.plugins.core.base import Finding
from pwnproxy.plugins.core.chain import create_chain, DetectionDepth
from pwnproxy.shared.scan.stages.xxe_stages import (
    XxeErrorBasedStage,
    JSONMutateStage,
    XxeOOBStage,
)
from pwnproxy.shared.scan.replayers.xxe import XxeReplayer
from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.shared.models import Flow

logger = logging.getLogger(__name__)


class XXEScanner:
    """High-level scanner that builds a detection chain for XXE."""

    def __init__(
        self,
        replayer: XxeReplayer,
        depth: DetectionDepth = DetectionDepth.FAST,
        evasion: str = "none",
        error_template: str = "",
        json_template: str = "",
        oob_template: str = "",
    ):
        self._replayer = replayer
        self._depth = depth
        self._evasion = evasion

        self.chain = create_chain(
            stages=[
                XxeErrorBasedStage(self._replayer, evasion_level=self._evasion, entity_xml=error_template),
                JSONMutateStage(self._replayer, evasion_level=self._evasion, xml_template=json_template),
                XxeOOBStage(self._replayer, evasion_level=self._evasion, oob_template=oob_template),
            ],
            depth=self._depth,
        )

    async def scan(self, flow: Flow, points: list[InjectionPoint]) -> list[Finding]:
        """Run the detection chain for a given flow."""
        findings: list[Finding] = []
        async for f in self.chain.run(flow, points):
            findings.append(f)
        return findings