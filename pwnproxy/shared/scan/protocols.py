"""Protocols for replayer type checking.

Defines structural typing protocols so DetectionStage instances can
validate at load time that they received a compatible replayer,
without being coupled to a concrete class.
"""

from typing import Optional, Protocol, runtime_checkable

import httpx

from pwnproxy.shared.scan.params import InjectionPoint


@runtime_checkable
class XMLMutableReplayer(Protocol):
    """Replayer capable of mutating XML/SOAP document bodies.

    Stages that need XML mutation (XXE ErrorBasedStage, JSONMutateStage,
    OOBStage) check ``isinstance(replayer, XMLMutableReplayer)`` in
    their constructor and raise a clear ``TypeError`` on mismatch.

    The base ``RequestReplayer`` does **not** implement this protocol —
    only ``XxeReplayer`` and future ``SoapReplayer`` subclasses do.
    """

    async def replay(
        self,
        point: InjectionPoint,
        payload: str,
        timeout: float = 10.0,
        evasion_level: str = "none",
    ) -> Optional[httpx.Response]:
        """Send a request with the given payload injected."""
        ...

    def mutate_xml_body(self, body: str, payload: str) -> str:
        """Return *body* with *payload* injected as an XML entity.

        This is the core XML mutation primitive. Stages call this
        before sending the request.
        """
        ...