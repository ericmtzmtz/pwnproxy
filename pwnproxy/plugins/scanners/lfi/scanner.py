'''LFI scanner using DetectionChain.

Orchestrates LFI detection stages (Simple, PHPWrapper, OOB)
via the shared DetectionChain framework.
'''

from __future__ import annotations

import logging

from pwnproxy.plugins.core.base import Finding
from pwnproxy.plugins.core.chain import DetectionChain, create_chain, DetectionDepth
from pwnproxy.shared.scan.stages.lfi_stages import (
    SimpleStage,
    PHPWrapperStage,
    LfiOOBStage,
)
from pwnproxy.shared.scan.replayer import RequestReplayer
from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.shared.models import Flow

logger = logging.getLogger(__name__)


class LFIScanner:
    """High-level scanner that builds a detection chain for LFI."""

    def __init__(
        self,
        replayer: RequestReplayer,
        payloads: list,
        php_payloads: list,
        matcher,
        depth: DetectionDepth = DetectionDepth.FAST,
        evasion: str = "none",
    ):
        self._replayer = replayer

        self.chain = create_chain(
            stages=[
                SimpleStage(self._replayer, payloads, matcher, evasion_level=evasion),
                PHPWrapperStage(self._replayer, php_payloads, matcher, evasion_level=evasion),
                LfiOOBStage(self._replayer, evasion_level=evasion),
            ],
            depth=depth,
        )

    async def scan(self, flow: Flow, points: list[InjectionPoint]) -> list[Finding]:
        """Run the detection chain for a given flow."""
        findings: list[Finding] = []
        async for f in self.chain.run(flow, points):
            findings.append(f)
        return findings
