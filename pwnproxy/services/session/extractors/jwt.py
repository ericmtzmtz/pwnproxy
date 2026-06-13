import json as json_mod
import logging
from typing import Optional

from pwnproxy.shared.models import Flow
from pwnproxy.services.session.models import TokenCandidate

logger = logging.getLogger(__name__)

JWT_FIELD_NAMES = {"token", "access_token", "id_token", "refresh_token"}


def extract(flow: Flow) -> list[TokenCandidate]:
    candidates: list[TokenCandidate] = []

    auth = flow.request_headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:]
        if token:
            candidates.append(
                TokenCandidate(
                    token_type="jwt",
                    token_value=token,
                    label="Bearer",
                    source_url=flow.url,
                    source_flow_id=flow.id,
                )
            )

    body = _get_text_body(flow)
    if body:
        try:
            data = json_mod.loads(body)
        except json_mod.JSONDecodeError:
            return candidates

        for field in JWT_FIELD_NAMES:
            val = _deep_get(data, field)
            if val and isinstance(val, str) and len(val.split(".")) == 3:
                candidates.append(
                    TokenCandidate(
                        token_type="jwt",
                        token_value=val,
                        label=field,
                        source_url=flow.url,
                        source_flow_id=flow.id,
                    )
                )

    return candidates


def _get_text_body(flow: Flow) -> Optional[str]:
    if flow.request_body is None:
        return None
    ct = flow.request_headers.get("content-type", "").lower()
    for skip in ("image/", "audio/", "video/", "application/octet-stream"):
        if ct.startswith(skip):
            return None
    return flow.request_body.decode("utf-8", "replace")


def _deep_get(data: dict, key: str) -> object:
    parts = key.split(".")
    d = data
    for p in parts:
        if isinstance(d, dict):
            d = d.get(p, {})
        else:
            return None
    return d if d != {} else None
