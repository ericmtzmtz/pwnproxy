import re
from enum import Enum
from typing import Optional


class ReflectionContext(str, Enum):
    HTML_BODY = "html_body"
    HTML_ATTR = "html_attr"
    JS_STRING = "js_string"
    URL = "url"
    HTML_COMMENT = "html_comment"
    SVG_NAMESPACE = "svg_namespace"
    UNKNOWN = "unknown"


# A reflection in one of these contexts is NOT XSS by itself — it only becomes
# so if the payload breaks out of the surrounding delimiter/context.
NON_EXEC_WITHOUT_BREAKOUT = {
    ReflectionContext.HTML_ATTR,
    ReflectionContext.JS_STRING,
    ReflectionContext.URL,
    ReflectionContext.HTML_COMMENT,
}

_EVENT_HANDLER_RE = re.compile(r"\bon\w+\s*=", re.I)
_JS_URI_RE = re.compile(r"^\s*javascript\s*:|^\s*data\s*:", re.I)
_JS_BREAK_CHARS = ("'", '"', "`")


class ContextAnalyzer:
    def analyze(self, body: str, canary: str) -> list[ReflectionContext]:
        if not body or not canary:
            return [ReflectionContext.UNKNOWN]

        positions = self._find_positions(body, canary)
        contexts: list[ReflectionContext] = []
        for pos, _ in positions:
            ctx = self._detect_context(body, canary, pos)
            if ctx not in contexts:
                contexts.append(ctx)
        return contexts or [ReflectionContext.UNKNOWN]

    def _find_positions(self, body: str, canary: str) -> list[tuple[int, int]]:
        positions: list[tuple[int, int]] = []
        start = 0
        while True:
            pos = body.find(canary, start)
            if pos == -1:
                break
            positions.append((pos, pos + len(canary)))
            start = pos + 1
        return positions

    def _detect_context(self, body: str, canary: str, pos: int) -> ReflectionContext:
        ctx = self._check_html_comment(body, canary, pos)
        if ctx:
            return ctx
        ctx = self._check_js_string(body, canary, pos)
        if ctx:
            return ctx
        ctx = self._check_svg_namespace(body, canary, pos)
        if ctx:
            return ctx
        ctx = self._check_url(body, canary, pos)
        if ctx:
            return ctx
        ctx = self._check_html_attr(body, canary, pos)
        if ctx:
            return ctx
        ctx = self._check_html_body(body, canary, pos)
        if ctx:
            return ctx
        return ReflectionContext.UNKNOWN

    def _check_html_comment(self, body: str, canary: str, pos: int) -> Optional[ReflectionContext]:
        before = body[max(0, pos - 100):pos]
        after = body[pos + len(canary):pos + len(canary) + 100]
        if re.search(r'<!--\s*$', before) and re.search(r'^\s*-->', after):
            return ReflectionContext.HTML_COMMENT
        if '<!--' in before and '-->' not in before:
            last_comment = before.rfind('<!--')
            after_comment = before[last_comment:]
            if '-->' not in after_comment:
                return ReflectionContext.HTML_COMMENT
        return None

    def _check_js_string(self, body: str, canary: str, pos: int) -> Optional[ReflectionContext]:
        if not body or not canary:
            return None
        before = body[max(0, pos - 200):pos]
        after = body[pos + len(canary):pos + len(canary) + 200]

        if re.search(r'<script[^>]*>', before, re.I) and re.search(r'</script>', after, re.I):
            return ReflectionContext.JS_STRING
        if re.search(r'(?:var|let|const|function)\s+\w+\s*[=:]\s*["\']', before) and re.search(r'["\'\s;,]', after[:5]):
            return ReflectionContext.JS_STRING
        if '"' not in before[-50:] and "'" not in before[-50:]:
            return None
        quote_char = None
        for ch in reversed(before[-50:]):
            if ch in ("'", '"', '`'):
                quote_char = ch
                break
        if quote_char and quote_char not in after[:50]:
            quote_idx = before.rfind(quote_char)
            between = before[quote_idx:]
            if '>' in between and '<' in between:
                return None
            return ReflectionContext.JS_STRING
        return None

    def _check_svg_namespace(self, body: str, canary: str, pos: int) -> Optional[ReflectionContext]:
        before = body[max(0, pos - 200):pos]
        if re.search(r'xlink:href\s*=\s*["\']', before, re.I):
            return ReflectionContext.SVG_NAMESPACE
        if re.search(r'href\s*=\s*["\']', before, re.I):
            preceding = body[max(0, pos - 400):pos]
            if re.search(r'<svg[^>]*>', preceding, re.I):
                return ReflectionContext.SVG_NAMESPACE
        return None

    def _check_url(self, body: str, canary: str, pos: int) -> Optional[ReflectionContext]:
        before = body[max(0, pos - 100):pos]
        m = re.search(r'(href|src|action)\s*=\s*["\']([^"\']*)$', before, re.I)
        if m:
            if canary in m.group(0):
                return None
            return ReflectionContext.URL
        return None

    def _check_html_attr(self, body: str, canary: str, pos: int) -> Optional[ReflectionContext]:
        before = body[max(0, pos - 100):pos]
        if re.search(r'\w+\s*=\s*["\'][^"\']*$', before):
            return ReflectionContext.HTML_ATTR
        if '"' in before or "'" in before:
            return None
        return None

    def _check_html_body(self, body: str, canary: str, pos: int) -> Optional[ReflectionContext]:
        before = body[max(0, pos - 100):pos]
        after = body[pos + len(canary):pos + len(canary) + 100]
        in_tag = '<' in before and '>' not in before[-50:]
        if in_tag:
            return None
        if re.search(r'>\s*[^<]*$', before) or re.search(r'^[^<]*<', after):
            return ReflectionContext.HTML_BODY
        return None

    def is_exploitable(self, body: str, payload: str) -> tuple[bool, list[ReflectionContext], str]:
        """Single decision point for whether a reflected payload is exploitable.

        ``body`` is the reflected HTTP response; ``payload`` is the injected
        value. Returns ``(exploitable, contexts, reason)``.

        A payload is only exploitable when it appears UNESCAPED (the raw
        payload string is present verbatim — an HTML-escaped double) AND it
        actually breaks out of, or executes within, its reflection context.
        Mere reflection is never enough.
        """
        if not body or not payload:
            return (False, [], "no body or payload")
        if payload not in body:
            return (False, self.analyze(body, payload), "payload not reflected unescaped")

        contexts = self.analyze(body, payload)
        for ctx in contexts:
            if ctx in NON_EXEC_WITHOUT_BREAKOUT:
                if self._breaks_out(ctx, body, payload):
                    return (True, [ctx], f"{ctx.value} breakout")
            elif ctx == ReflectionContext.HTML_BODY:
                return (True, [ctx], "html_body unescaped markup")
            elif ctx == ReflectionContext.SVG_NAMESPACE:
                if self._has_js_uri(payload):
                    return (True, [ctx], "svg_namespace javascript/data uri")
        return (False, contexts, "reflection without exploitable breakout")

    @staticmethod
    def _breaks_out(ctx: ReflectionContext, body: str, payload: str) -> bool:
        """Context-specific breakout check. The payload is known to be present verbatim."""
        if ctx == ReflectionContext.HTML_ATTR:
            return bool(
                _EVENT_HANDLER_RE.search(payload)
                or _JS_URI_RE.match(payload)
            )
        if ctx == ReflectionContext.JS_STRING:
            return any(ch in payload for ch in _JS_BREAK_CHARS) or "</script>" in payload.lower()
        if ctx == ReflectionContext.URL:
            return bool(_JS_URI_RE.match(payload))
        if ctx == ReflectionContext.HTML_COMMENT:
            return "-->" in payload
        return False

    @staticmethod
    def _has_js_uri(payload: str) -> bool:
        return bool(_JS_URI_RE.search(payload))
