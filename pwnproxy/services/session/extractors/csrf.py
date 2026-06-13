import json as json_mod
import logging
from typing import Optional
from urllib.parse import parse_qs

from pwnproxy.shared.models import Flow
from pwnproxy.services.session.models import TokenCandidate

logger = logging.getLogger(__name__)

CSRF_HEADERS = {"x-csrf-token", "x-xsrf-token", "csrf-token"}
CSRF_BODY_FIELDS = {"csrf_token", "_csrf", "csrfmiddlewaretoken", "authenticity_token"}


def extract(flow: Flow) -> list[TokenCandidate]:
    candidates: list[TokenCandidate] = []

    for header_name in CSRF_HEADERS:
        val = flow.request_headers.get(header_name, "")
        if val:
            candidates.append(
                TokenCandidate(
                    token_type="csrf",
                    token_value=val.strip(),
                    label=header_name,
                    source_url=flow.url,
                    source_flow_id=flow.id,
                )
            )

    body = _get_form_body(flow)
    if body is not None:
        for field in CSRF_BODY_FIELDS:
            val = body.get(field)
            if val and isinstance(val, list) and val[0]:
                candidates.append(
                    TokenCandidate(
                        token_type="csrf",
                        token_value=val[0].strip(),
                        label=field,
                        source_url=flow.url,
                        source_flow_id=flow.id,
                    )
                )

    json_body = _get_json_body(flow)
    if json_body is not None:
        for field in CSRF_BODY_FIELDS:
            val = json_body.get(field)
            if val and isinstance(val, str):
                candidates.append(
                    TokenCandidate(
                        token_type="csrf",
                        token_value=val.strip(),
                        label=field,
                        source_url=flow.url,
                        source_flow_id=flow.id,
                    )
                )

    return candidates


def _get_form_body(flow: Flow) -> Optional[dict[str, list[str]]]:
    if flow.request_body is None:
        return None
    ct = flow.request_headers.get("content-type", "").lower()
    if "application/x-www-form-urlencoded" not in ct:
        return None
    return parse_qs(
        flow.request_body.decode("utf-8", "replace"), keep_blank_values=True
    )


def _get_json_body(flow: Flow) -> Optional[dict]:
    if flow.request_body is None:
        return None
    ct = flow.request_headers.get("content-type", "").lower()
    if "application/json" not in ct:
        return None
    try:
        return json_mod.loads(flow.request_body.decode("utf-8", "replace"))
    except json_mod.JSONDecodeError:
        return None
