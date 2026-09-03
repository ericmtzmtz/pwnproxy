"""Heuristic detection of WAF / reverse-proxy blocking responses.

Pure helpers (no I/O) shared by scanners. A scanner that sees an HTTP error it
cannot explain (e.g. a 5xx induced by an injection payload with no DB error
signature in the body) must decide whether the error is the application
executing the payload or an intermediary blocking it. These helpers give cheap,
deterministic signals from the response body and headers.
"""
from __future__ import annotations

import re
from typing import Mapping, Optional

# Body markers that identify a WAF/proxy block/error page. Only meaningful when
# the HTTP status is an error (>= 400) — a 200 page may contain the word
# "blocked" incidentally (e.g. UI copy), which must not count.
BLOCK_PAGE_PATTERNS: list[re.Pattern] = [
    re.compile(r"request\s+rejected", re.I),
    re.compile(r"attention\s+required", re.I),
    re.compile(r"mod[_\s]?security", re.I),
    re.compile(r"the\s+request\s+was\s+blocked", re.I),
    re.compile(r"access\s+denied", re.I),
    re.compile(r"cloudflare\s+ray", re.I),
    re.compile(r"incapsula", re.I),
    re.compile(r"akamai", re.I),
    re.compile(r"imperva", re.I),
    re.compile(r"sucuri", re.I),
    re.compile(r"barracuda", re.I),
    re.compile(r"\bf5\b", re.I),
    re.compile(r"not\s+allowed\s+to\s+access", re.I),
    re.compile(r"blocked\s+by\s+(?:the\s+)?(?:firewall|waf|security)", re.I),
]

# Header-name -> pattern. Header names are matched case-insensitively; values are
# checked against the pattern.
BLOCK_HEADER_PATTERNS: dict[str, re.Pattern] = {
    "server": re.compile(r"cloudflare|akamai|sucuri|barracuda|incapsula|imperva|f5", re.I),
    "cf-ray": re.compile(r".+"),
    "x-waf": re.compile(r".+"),
    "x-waf-request-id": re.compile(r".+"),
    "x-deny-reason": re.compile(r".+"),
    "x-sucuri-id": re.compile(r".+"),
    "x-cdn": re.compile(r"incapsula|akamai", re.I),
    "x-powered-by": re.compile(r"waf|akamai|imperva", re.I),
}

# Statuses that indicate an intermediary rate limit / bot defense rather than a
# vulnerability signal. A 502 (bad gateway) is treated separately: it is not a
# block page but is also not attributable to the payload.
RATE_LIMIT_STATUSES = {429, 503}

# Body bytes inspected for block markers; block pages are short.
_BODY_SCAN_LIMIT = 2048


def is_rate_limit_status(status: Optional[int]) -> bool:
    """True for intermediary rate-limit / bot-defense statuses (429, 503)."""
    return status in RATE_LIMIT_STATUSES


def looks_like_block_page(
    status: Optional[int],
    body: Optional[str],
    headers: Optional[Mapping[str, str]] = None,
) -> bool:
    """True when an error response appears to come from a WAF/proxy block page.

    The body is only consulted when ``status >= 400`` so that harmless 2xx/3xx
    pages containing words like "blocked" or "access denied" do not false-positive.
    Header markers are only consulted on error statuses too (a 200 behind a WAF
    CDN header is normal traffic, not a block).
    """
    if status is None or status < 400:
        return False

    if headers:
        for name, pattern in BLOCK_HEADER_PATTERNS.items():
            value = _header_value(headers, name)
            if value is not None and pattern.search(value):
                return True

    if body:
        sample = body[:_BODY_SCAN_LIMIT]
        for pattern in BLOCK_PAGE_PATTERNS:
            if pattern.search(sample):
                return True

    return False


def _header_value(headers: Mapping[str, str], name: str) -> Optional[str]:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None
