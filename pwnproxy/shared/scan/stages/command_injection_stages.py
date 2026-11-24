"""Command-injection detection stage.

The stage only confirms when the injected response *adds* command output that
was not already there: a signature that also matches the baseline response
(same request without a payload) is page text, not the result of an injection.
Bodies that cannot be read as text (PDF, images, archives) are skipped before
any payload is sent.
"""

import logging

from pwnproxy.shared.models import Flow
from pwnproxy.shared.scan.content_types import (
    header_value,
    is_known_binary,
    is_textual,
    response_is_textual,
)
from pwnproxy.shared.scan.finding import Finding
from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.shared.scan.replayer import RequestReplayer
from pwnproxy.shared.scan.stage import DetectionDepth, DetectionStage, StageResult

logger = logging.getLogger(__name__)


class CommandInjectionStage(DetectionStage):
    """Detects command injection by injecting OS commands and checking response.

    A finding is only emitted when all three hold:

    1. the injected response is text (``text/*``, JSON, XML, JS, or a body with
       no declared type that decodes as UTF-8); a declared binary type
       (``application/pdf``, ``image/*``, archives, ...) skips the whole flow
       without sending a single request when the captured flow carries it;
    2. the matched signature does **not** match the baseline response — the
       captured response of the flow, or one clean request per injection point
       reused for every payload when the flow did not capture a body;
    3. the injected ``has_command_output`` callable reports a signature specific
       enough to be command output (see the scanner's ``signatures`` module).

    The baseline check is enforced here as well as in the detector: if the
    baseline already matches the same technique, the finding is dropped even if
    an injected detector forgot to compare.
    """

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
        """Create the stage.

        Args:
            replayer: HTTP replayer used for the clean and injected requests.
            payloads: Objects with ``.value`` and ``.technique`` attributes.
            has_command_output: Callable ``(body, baseline="") -> (bool, technique)``
                owned by the scanner plugin (its patterns live there).
            get_evidence: Callable ``(body, technique) -> str`` snippet for the finding.
            evasion_level: Evasion profile name (``none``/``light``/``aggressive``).
            timeout: Per-request timeout in seconds.
        """
        self._replayer = replayer
        self._payloads = payloads
        # Injected by the scanner plugin: response-body detector and evidence
        # formatter live with the plugin's signatures, not in shared.
        self._has_command_output = has_command_output
        self._get_evidence = get_evidence
        self._evasion = evasion_level
        self._timeout = timeout

    async def execute(self, flow: Flow, injection_points: list[InjectionPoint]) -> StageResult:
        """Run the stage over every injection point of one flow.

        Args:
            flow: The captured flow (its response, when present, is the baseline).
            injection_points: Points extracted from ``flow``.

        Returns:
            StageResult with at most one finding per injection point.
        """
        findings: list[Finding] = []
        confirmed: set[tuple] = set()

        # A binary response cannot contain command output, so a captured PDF /
        # image / archive is skipped without a single extra request.
        captured_type = header_value(flow.response_headers, "content-type")
        if is_known_binary(captured_type):
            logger.info(
                "CommandInjectionStage: captured response of %s is binary (%s) — skipping",
                flow.url, captured_type,
            )
            return StageResult(findings=findings, confirmed_points=confirmed)

        for point in injection_points:
            if self._deadline_exceeded():
                break

            baseline = await self._baseline(flow, point)
            if baseline is None:
                # No usable baseline -> cannot attribute output to the payload.
                logger.info(
                    "CommandInjectionStage: no baseline for %s — skipping (fail closed)",
                    point.key,
                )
                continue
            baseline_text, baseline_textual = baseline
            if not baseline_textual:
                logger.info(
                    "CommandInjectionStage: baseline of %s is not text — skipping",
                    point.key,
                )
                continue
            # Defence in depth: a technique that already matches the baseline is
            # page text, whatever the injected detector says.
            baseline_detected, baseline_technique = self._has_command_output(baseline_text)

            for payload in self._payloads:
                try:
                    resp = await self._replayer.replay(
                        point, payload.value,
                        timeout=self._timeout,
                        evasion_level=self._evasion,
                    )
                    if resp is None:
                        continue
                    # A binary answer to a payload (e.g. the endpoint switched to
                    # a file download) is never comparable command output.
                    if not response_is_textual(resp):
                        continue

                    body = resp.text or ""
                    detected, technique = self._has_command_output(body, baseline_text)

                    if detected and baseline_detected and baseline_technique == technique:
                        logger.info(
                            "CommandInjectionStage: %r output already in baseline of %s — not attributable",
                            technique, point.key,
                        )
                        continue

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

    async def _baseline(self, flow: Flow, point: InjectionPoint) -> tuple[str, bool] | None:
        """Return ``(text, is_textual)`` for the response without a payload.

        Uses the body captured by the proxy when it is available and complete
        (free), otherwise sends **one** clean request for the point — the result
        is reused for every payload of that point.

        Args:
            flow: Captured flow, possibly without a response.
            point: Injection point whose clean response is the baseline.

        Returns:
            ``(text, is_textual)``, or ``None`` when no baseline could be
            obtained (the caller then skips the point — fail closed).
        """
        if flow.response_body and not flow.response_body_truncated:
            content_type = header_value(flow.response_headers, "content-type")
            raw = flow.response_body
            text = (
                raw.decode("utf-8", "replace")
                if isinstance(raw, (bytes, bytearray))
                else str(raw)
            )
            return text, is_textual(content_type, raw)
        resp = await self._replayer.send_clean(point, timeout=10.0)
        if resp is None:
            return None
        return resp.text or "", response_is_textual(resp)
