import logging
import re
from typing import Optional

from pwnproxy.core.models import Flow
from pwnproxy.modules.session_manager.models import TokenCandidate

logger = logging.getLogger(__name__)

SESSION_PATTERN = re.compile(
    r"(session|sid|token|jwt|auth|csrf|xsrf)", re.IGNORECASE
)


def extract(flow: Flow) -> list[TokenCandidate]:
    candidates: list[TokenCandidate] = []

    candidates.extend(_from_header(flow.request_headers.get("cookie", ""), flow))
    candidates.extend(_from_set_cookie(flow.response_headers, flow))

    return candidates


def _from_header(cookie_header: str, flow: Flow) -> list[TokenCandidate]:
    candidates = []
    if not cookie_header:
        return candidates
    for pair in cookie_header.split(";"):
        pair = pair.strip()
        if "=" not in pair:
            continue
        name, _, val = pair.partition("=")
        name = name.strip()
        val = val.strip()
        if SESSION_PATTERN.search(name):
            candidates.append(
                TokenCandidate(
                    token_type="cookie",
                    token_value=val,
                    label=name,
                    source_url=flow.url,
                    source_flow_id=flow.id,
                )
            )
    return candidates


def _from_set_cookie(
    headers: dict[str, str], flow: Flow
) -> list[TokenCandidate]:
    candidates = []
    raw = headers.get("set-cookie", "")
    if not raw:
        return candidates

    for part in raw.split(";"):
        part = part.strip()
        if "=" in part and SESSION_PATTERN.search(part.split("=")[0]):
            name, _, val = part.partition("=")
            name = name.strip()
            val = val.strip()
            candidates.append(
                TokenCandidate(
                    token_type="cookie",
                    token_value=val,
                    label=name,
                    source_url=flow.url,
                    source_flow_id=flow.id,
                )
            )
            break
    return candidates
