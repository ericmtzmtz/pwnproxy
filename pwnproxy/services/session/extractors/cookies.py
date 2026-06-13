import logging
import re
from typing import Optional

from pwnproxy.shared.models import Flow
from pwnproxy.services.session.models import TokenCandidate

logger = logging.getLogger(__name__)

SESSION_PATTERN = re.compile(
    r"(session|sid|token|jwt|auth|csrf|xsrf)", re.IGNORECASE
)


def extract(flow: Flow) -> list[TokenCandidate]:
    candidates: list[TokenCandidate] = []

    candidates.extend(_from_header(flow.request_headers.get("cookie", ""), flow))
    if flow.response_headers:
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

    raw = next(
        (v for k, v in headers.items() if k.lower() == "set-cookie"),
        None
    )
    if not raw:
        return candidates

    # Multiple Set-Cookie headers may be comma-joined by dict dedup
    for cookie_part in re.split(r",(?=[^ ;]+=)", raw):
        cookie_part = cookie_part.strip()
        if "=" not in cookie_part:
            continue
        name, _, val = cookie_part.partition("=")
        name = name.strip()
        val = val.split(";")[0].strip()
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
