import logging
from typing import Optional
from urllib.parse import urlparse

from pwnproxy.shared.models import Flow
from pwnproxy.shared.scan.params import InjectionPoint, extract as extract_params

logger = logging.getLogger(__name__)

URL_LIKE_NAMES = {
    "url", "uri", "path", "dest", "redirect", "next", "callback",
    "webhook", "return", "continue", "file", "load", "proxy", "fetch",
    "cors", "proxytohost", "goto", "target", "endpoint", "host",
    "domain", "site", "page", "document", "resource", "source",
}


class SsrfExtractor:
    def extract_url_params(self, flow: Flow) -> list[InjectionPoint]:
        all_points = extract_params(flow)
        return [
            p for p in all_points
            if self._is_url_like(p.name)
        ]

    def extract_redirect_params(self, flow: Flow) -> list[InjectionPoint]:
        if not (300 <= (flow.status_code or 0) < 400):
            return []

        location = flow.response_headers.get("location", "")
        if not location:
            return []

        all_points = extract_params(flow)
        candidates: list[InjectionPoint] = []

        for p in all_points:
            if p.value and p.value in location:
                candidates.append(p)

        if candidates:
            return candidates

        for p in all_points:
            if self._is_url_like(p.name):
                candidates.append(p)

        return candidates

    def _is_url_like(self, name: str) -> bool:
        clean = name.lower().replace("_", "").replace("-", "").replace(".", "")
        return clean in URL_LIKE_NAMES or any(
            url_name in clean for url_name in URL_LIKE_NAMES
        )
