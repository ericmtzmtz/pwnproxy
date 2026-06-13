import json
import logging
from dataclasses import dataclass
from typing import Optional
from urllib.parse import parse_qs, urlparse

from pwnproxy.shared.models import Flow

logger = logging.getLogger(__name__)

SKIP_CONTENT_TYPES = {
    "application/octet-stream",
    "image/png", "image/jpeg", "image/gif", "image/webp",
    "image/svg+xml", "image/*",
}

INJECTABLE_HEADERS = {"referer", "x-forwarded-for", "user-agent"}


@dataclass
class InjectionPoint:
    name: str
    value: str
    location: str
    flow_id: str
    method: str
    url: str
    host: str
    path: str
    original_headers: dict[str, str]
    original_body: Optional[str]

    @property
    def key(self) -> tuple:
        return (self.method, self.host + self.path, self.name, self.location)


def extract(flow: Flow) -> list[InjectionPoint]:
    points: list[InjectionPoint] = []
    parsed = urlparse(flow.url)
    host = parsed.netloc
    path = parsed.path
    body_text = _get_body_text(flow)

    points.extend(_extract_query(flow, host, path, body_text))
    points.extend(_extract_body(flow, host, path, body_text))
    points.extend(_extract_cookies(flow, host, path, body_text))
    points.extend(_extract_headers(flow, host, path, body_text))
    return points


def _get_body_text(flow: Flow) -> Optional[str]:
    if flow.request_body is None:
        return None
    ct = flow.request_headers.get("content-type", "").lower()
    for skip in SKIP_CONTENT_TYPES:
        if ct.startswith(skip.rstrip("*")):
            return None
    return flow.request_body.decode("utf-8", "replace")


def _extract_query(
    flow: Flow, host: str, path: str, body_text: Optional[str]
) -> list[InjectionPoint]:
    points = []
    parsed = urlparse(flow.url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    for name, values in params.items():
        for val in values:
            points.append(InjectionPoint(
                name=name, value=val, location="query",
                flow_id=flow.id, method=flow.method, url=flow.url,
                host=host, path=path,
                original_headers=flow.request_headers,
                original_body=body_text,
            ))
    return points


def _extract_body(
    flow: Flow, host: str, path: str, body_text: Optional[str]
) -> list[InjectionPoint]:
    points = []
    if body_text is None:
        return points
    ct = flow.request_headers.get("content-type", "").lower()

    if "application/x-www-form-urlencoded" in ct:
        params = parse_qs(body_text, keep_blank_values=True)
        for name, values in params.items():
            for val in values:
                points.append(InjectionPoint(
                    name=name, value=val, location="body",
                    flow_id=flow.id, method=flow.method, url=flow.url,
                    host=host, path=path,
                    original_headers=flow.request_headers,
                    original_body=body_text,
                ))
    elif "application/json" in ct:
        try:
            data = json.loads(body_text)
            _extract_json_keys("", data, points, flow, host, path, body_text)
        except json.JSONDecodeError:
            pass
    return points


def _extract_json_keys(
    prefix: str, data, points: list[InjectionPoint],
    flow: Flow, host: str, path: str, body_text: Optional[str],
) -> None:
    if isinstance(data, dict):
        for k, v in data.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                _extract_json_keys(key, v, points, flow, host, path, body_text)
            else:
                points.append(InjectionPoint(
                    name=key, value=str(v), location="body",
                    flow_id=flow.id, method=flow.method, url=flow.url,
                    host=host, path=path,
                    original_headers=flow.request_headers,
                    original_body=body_text,
                ))
    elif isinstance(data, list):
        for i, item in enumerate(data):
            key = f"{prefix}[{i}]"
            _extract_json_keys(key, item, points, flow, host, path, body_text)


def _extract_cookies(
    flow: Flow, host: str, path: str, body_text: Optional[str]
) -> list[InjectionPoint]:
    points = []
    raw = flow.request_headers.get("cookie", "")
    if not raw:
        return points
    for pair in raw.split(";"):
        pair = pair.strip()
        if "=" in pair:
            name, _, val = pair.partition("=")
            points.append(InjectionPoint(
                name=name.strip(), value=val.strip(), location="cookie",
                flow_id=flow.id, method=flow.method, url=flow.url,
                host=host, path=path,
                original_headers=flow.request_headers,
                original_body=body_text,
            ))
    return points


def _extract_headers(
    flow: Flow, host: str, path: str, body_text: Optional[str]
) -> list[InjectionPoint]:
    points = []
    for key, val in flow.request_headers.items():
        if key.lower() in INJECTABLE_HEADERS:
            points.append(InjectionPoint(
                name=key, value=val, location="header",
                flow_id=flow.id, method=flow.method, url=flow.url,
                host=host, path=path,
                original_headers=flow.request_headers,
                original_body=body_text,
            ))
    return points
