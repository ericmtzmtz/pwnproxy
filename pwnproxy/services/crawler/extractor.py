"""URL extraction from proxied HTTP responses.

Sources: HTML attributes (a/form/script/link/img/iframe/source/area),
Location / Content-Location headers, quoted URLs inside JavaScript and
JSON bodies. Every candidate is resolved against the response base URL
and normalized before being returned.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Iterable, Optional
from urllib.parse import urljoin, urlsplit, urlunsplit

#: (tag, attribute) -> source label
_ATTR_SOURCES: dict[tuple[str, str], str] = {
    ("a", "href"): "a",
    ("form", "action"): "form",
    ("script", "src"): "script",
    ("link", "href"): "link",
    ("img", "src"): "img",
    ("iframe", "src"): "iframe",
    ("source", "src"): "source",
    ("area", "href"): "area",
}

_SKIP_PREFIXES = ("javascript:", "mailto:", "data:", "tel:", "#")

# Quoted absolute http(s) URLs — applies to any body (JS, JSON, inline attrs).
_ABSOLUTE_RE = re.compile(r"[\"'](https?://[^\"'<>\\\s]{4,})[\"']")
# Quoted root-relative paths — only applied to <script> contents or JSON bodies.
_RELATIVE_RE = re.compile(r"[\"'](/[^\"'<>\\\s]{1,300})[\"']")


def normalize_url(raw: str, base_url: str) -> Optional[str]:
    """Resolve ``raw`` against ``base_url`` and normalize it.

    Normalization: strip fragment, sort query params, remove trailing slash,
    lowercase scheme/host. Returns None for non-http(s) or unparseable input.
    """
    if not raw:
        return None
    candidate = raw.strip().strip("'\"")
    if not candidate:
        return None
    lowered = candidate.lower()
    if any(lowered.startswith(p) for p in _SKIP_PREFIXES):
        return None
    try:
        joined = urljoin(base_url, candidate)
        parts = urlsplit(joined)
    except Exception:
        return None
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None
    scheme = parts.scheme.lower()
    netloc = parts.netloc.lower()
    path = parts.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
        if not path:
            path = "/"
    # Sort raw query pairs without re-encoding values (keeps fidelity).
    query = "&".join(sorted(parts.query.split("&"))) if parts.query else ""
    return urlunsplit((scheme, netloc, path, query, ""))


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.found: list[tuple[str, str]] = []
        self._script_depth = 0
        self._script_chunks: list[str] = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag == "script":
            self._script_depth += 1
        for (attr_tag, attr_name), source in _ATTR_SOURCES.items():
            if attr_tag != tag:
                continue
            for name, value in attrs:
                if name == attr_name and value:
                    self.found.append((value, source))

    def handle_endtag(self, tag):
        if tag.lower() == "script" and self._script_depth > 0:
            self._script_depth -= 1

    def handle_data(self, data):
        if self._script_depth > 0 and data.strip():
            self._script_chunks.append(data)

    def close(self) -> None:
        super().close()

    @property
    def script_text(self) -> str:
        return "\n".join(self._script_chunks)


def _looks_like_path(candidate: str) -> bool:
    if not candidate.startswith("/") or len(candidate) < 2:
        return False
    if any(c.isspace() for c in candidate):
        return False
    # Reject obvious non-URL strings (regex-ish, template placeholders).
    if "{" in candidate or "}" in candidate or candidate.startswith("//"):
        return False
    return any(c.isalnum() for c in candidate)


def extract_urls(body: Optional[str], base_url: str, content_type: str = "") -> list[tuple[str, str]]:
    """Extract ``(normalized_url, source)`` pairs from a response body.

    Duplicates within the same body are collapsed; order is preserved.
    """
    if not body:
        return []
    parser = _LinkParser()
    try:
        parser.feed(body)
        parser.close()
    except Exception:
        pass

    results: list[tuple[str, str]] = []

    def _add(raw: str, source: str) -> None:
        normalized = normalize_url(raw, base_url)
        if normalized is not None:
            results.append((normalized, source))

    for raw, source in parser.found:
        _add(raw, source)

    script_text = parser.script_text
    for match in _ABSOLUTE_RE.finditer(body):
        _add(match.group(1), "js")
    for match in _ABSOLUTE_RE.finditer(script_text):
        _add(match.group(1), "js")

    is_json = "json" in (content_type or "").lower()
    rel_targets: Iterable[str] = (script_text, body) if is_json else (script_text,)
    for target in rel_targets:
        for match in _RELATIVE_RE.finditer(target):
            candidate = match.group(1)
            if _looks_like_path(candidate):
                _add(candidate, "js")

    seen: set[str] = set()
    unique: list[tuple[str, str]] = []
    for url, source in results:
        if url not in seen:
            seen.add(url)
            unique.append((url, source))
    return unique


def extract_from_headers(headers: dict, base_url: str) -> list[tuple[str, str]]:
    """Extract URLs from Location / Content-Location response headers."""
    results: list[tuple[str, str]] = []
    if not headers:
        return results
    for name, value in headers.items():
        lname = (name or "").lower()
        if lname in ("location", "content-location") and value:
            normalized = normalize_url(value, base_url)
            if normalized is not None:
                results.append((normalized, "location"))
    return results
