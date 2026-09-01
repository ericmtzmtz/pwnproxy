"""DOM XSS sink detection.

Static analysis of served JavaScript to detect whether an injected canary
travels toward a known DOM sink. This is an *inferred* signal (no JS
execution): a canary found inside the argument of a recognized sink is
treated as potential DOM XSS, while a canary anywhere else in the script is
not.

Sinks covered:
  - document.write / document.writeln
  - element.innerHTML / outerHTML / insertAdjacentHTML
  - eval / Function / setTimeout / setInterval with a string argument
  - location.href / location.assign / location.replace / document.location
  - window.open
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class DomSink:
    """A DOM sink with a regex that matches the canary inside its argument."""

    name: str
    # ``{canary}`` placeholder is replaced with ``re.escape(canary)``.
    pattern: str
    # Sink usage without requiring a canary (presence check for the
    # param-reads-location path).
    presence: str


# Pattern templates. ``{canary}`` is substituted at check time with the
# escaped canary so we only match the exact injected value, never random page
# text that happens to look like a canary.
_SINK_PATTERNS: list[tuple[str, str, str]] = [
    (
        "document.write",
        r"document\.writel?n?\s*\(\s*(?:[^()\n]*\|\s*)?[^()\n]*\{canary\}",
        r"document\.writel?n?\s*\(",
    ),
    (
        "innerHTML",
        r"\.innerHTML\s*=\s*(?:[^;]*(?:\+|=)\s*)*[^;]*\{canary\}[^;]*;?",
        r"\.innerHTML\s*=",
    ),
    (
        "outerHTML",
        r"\.outerHTML\s*=\s*(?:[^;]*(?:\+|=)\s*)*[^;]*\{canary\}[^;]*;?",
        r"\.outerHTML\s*=",
    ),
    (
        "insertAdjacentHTML",
        r"\.insertAdjacentHTML\s*\(\s*[^,]+,\s*[^)]*\{canary\}",
        r"\.insertAdjacentHTML\s*\(",
    ),
    (
        "eval",
        r"\beval\s*\(\s*[^)]*\{canary\}[^)]*\)",
        r"\beval\s*\(",
    ),
    (
        "Function",
        r"\bFunction\s*\(\s*[^)]*\{canary\}[^)]*\)",
        r"\bFunction\s*\(",
    ),
    (
        "setTimeout",
        r'\bsetTimeout\s*\(\s*["\'`][^)]*\{canary\}[^)]*\)',
        r"\bsetTimeout\s*\(",
    ),
    (
        "setInterval",
        r'\bsetInterval\s*\(\s*["\'`][^)]*\{canary\}[^)]*\)',
        r"\bsetInterval\s*\(",
    ),
    (
        "location.href",
        r"location\.href\s*(?:\+=|-=)?=\s*[^;]*?\{canary\}[^;]*;?",
        r"location\.href\s*(?:\+=|-=)?=",
    ),
    (
        "location.assign",
        r"location\.assign\s*\(\s*[^)]*\{canary\}[^)]*\)",
        r"location\.assign\s*\(",
    ),
    (
        "location.replace",
        r"location\.replace\s*\(\s*[^)]*\{canary\}[^)]*\)",
        r"location\.replace\s*\(",
    ),
    (
        "window.open",
        r"window\.open\s*\(\s*[^,)]*\{canary\}[^)]*\)",
        r"window\.open\s*\(",
    ),
    (
        "document.location",
        r"document\.location\s*[+.]?=?[\s'\"`]*(?:\+|\|)?[^;]*\{canary\}[^;]*;?",
        r"document\.location\s*[+.]?=?",
    ),
]

DOM_SINKS: list[DomSink] = [DomSink(name, pattern, presence) for name, pattern, presence in _SINK_PATTERNS]

# How a script reads a URL parameter from location (classic DOM XSS source).
# e.g. document.location.href.indexOf("default=")  /  split("default=")  /
# location.search.substring(...)  /  URLSearchParams.get("default")
_PARAM_READ_TEMPLATES = [
    r"location\.(?:href|search|hash|pathname)\b[^;]*?(?:indexOf|split|substring|substr|match|replace)\s*\(\s*[\"'`]&?\{param\}[^\"'`]*[\"'`]",
    r"URLSearchParams[^;]*?\.get\s*\(\s*[\"'`]?\{param\}[\"'`]?",
    r"location\.search[^;]*?[\"'`]?\{param\}[\"'`]?",
]


def _script_blocks(html: str) -> list[str]:
    """Extract inline ``<script>...</script>`` blocks (no src)."""
    blocks: list[str] = []
    for m in re.finditer(r"<script\b[^>]*>(.*?)</script>", html, re.I | re.S):
        tag = m.group(0)
        if r"src=" not in tag.lower():
            blocks.append(m.group(1))
    return blocks


def find_sinks(html: str, canary: str) -> list[DomSink]:
    """Return the sinks in ``html`` whose argument contains ``canary``.

    Only looks inside inline ``<script>`` blocks. A canary appearing in the
    HTML body (not in a script) is NOT considered a DOM sink signal.
    """
    if not html or not canary:
        return []
    escaped = re.escape(canary)
    hits: list[DomSink] = []
    for block in _script_blocks(html):
        for sink in DOM_SINKS:
            pattern = sink.pattern.replace(r"\{canary\}", escaped)
            if re.search(pattern, block, re.I):
                hits.append(sink)
    return hits


def find_sink_snippet(html: str, canary: str, sink: DomSink) -> str:
    """Return a short snippet around the canary inside the matching sink."""
    escaped = re.escape(canary)
    pattern = sink.pattern.replace(r"\{canary\}", escaped)
    for block in _script_blocks(html):
        m = re.search(pattern, block, re.I)
        if m:
            start = max(0, m.start() - 20)
            end = min(len(block), m.end() + 30)
            return block[start:end].strip()
    return ""


def find_param_location_sinks(html: str, param_name: str) -> list[DomSink]:
    """Detect classic DOM XSS sources: a script reads ``param_name`` from
    ``location.*`` (or URLSearchParams) and the same script block contains a
    recognized DOM sink.

    This covers targets like DVWA xss_d where the server does NOT reflect the
    injected value — the script parses ``document.location.href`` directly.
    """
    if not html or not param_name:
        return []
    escaped = re.escape(param_name)
    hits: list[DomSink] = []
    for block in _script_blocks(html):
        # The param is read from location somewhere in this block
        read = False
        for tmpl in _PARAM_READ_TEMPLATES:
            pattern = tmpl.replace(r"\{param\}", escaped)
            if re.search(pattern, block, re.I):
                read = True
                break
        if not read:
            continue
        # The same block writes to a DOM sink
        for sink in DOM_SINKS:
            if re.search(sink.presence, block, re.I):
                hits.append(sink)
    return hits


def find_param_location_snippet(html: str, param_name: str, sink: DomSink) -> str:
    """Return a snippet around the param read (location source) in the block."""
    escaped = re.escape(param_name)
    for block in _script_blocks(html):
        read_pos = None
        for tmpl in _PARAM_READ_TEMPLATES:
            pattern = tmpl.replace(r"\{param\}", escaped)
            m = re.search(pattern, block, re.I)
            if m:
                read_pos = m.start()
                break
        if read_pos is None:
            continue
        if not re.search(sink.presence, block, re.I):
            continue
        start = max(0, read_pos - 30)
        end = min(len(block), read_pos + 100)
        return block[start:end].strip()
    return ""
