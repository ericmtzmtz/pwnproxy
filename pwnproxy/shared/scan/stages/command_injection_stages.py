import logging

from pwnproxy.shared.models import Flow
from pwnproxy.shared.scan.finding import Finding
from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.shared.scan.replayer import RequestReplayer
from pwnproxy.shared.scan.stage import DetectionDepth, DetectionStage, StageResult

logger = logging.getLogger(__name__)


class CommandInjectionStage(DetectionStage):
    """Detects command injection by injecting OS commands and checking response."""
    
    order = 0
    min_depth = DetectionDepth.FAST
    capability = "command-injection"
    
    def __init__(
        self,
        replayer: RequestReplayer,
        payloads: list,
        has_command_output,
        get_evidence,
        evasion_level="none",
        timeout=5.0,
    ):
        self._replayer = replayer
        self._payloads = payloads
        # Injected by the scanner plugin: response-body detector and evidence
        # formatter live with the plugin's signatures, not in shared.
        self._has_command_output = has_command_output
        self._get_evidence = get_evidence
        self._evasion = evasion_level
        self._timeout = timeout
    
    async def execute(self, flow: Flow, injection_points: list[InjectionPoint]) -> StageResult:
        findings = []
        confirmed = set()
        
        for point in injection_points:
            if self._deadline_exceeded():
                break
            for payload in self._payloads:
                try:
                    resp = await self._replayer.replay(
                        point, payload.value,
                        timeout=self._timeout,
                        evasion_level=self._evasion,
                    )
                    if resp is None:
                        continue
                    
                    body = resp.text or ""
                    detected, technique = self._has_command_output(body)
                    
                    if detected:
                        evidence = self._get_evidence(body, technique)
                        findings.append(Finding(
                            scanner="command-injection",
                            url=point.url,
                            method=point.method,
                            param_name=point.name,
                            param_location=point.location,
                            technique=payload.technique,
                            severity="high",
                            confidence="confirmed",
                            payload=payload.value,
                            evidence=evidence,
                            timestamp=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
                        ))
                        confirmed.add(point.key)
                        break
                except Exception as e:
                    logger.debug(f"Command injection stage error: {e}")
        
        return StageResult(findings=findings, confirmed_points=confirmed)
