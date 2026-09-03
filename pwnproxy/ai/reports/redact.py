"""Export-boundary redaction: strip session cookies and credentials from report artifacts.

Redaction happens ONLY when building the report context — never on persisted
findings. It is conservative best-effort hygiene (no NER, no external deps):
values whose key/format clearly marks them as secrets are replaced with
``[redacted]``; technical evidence (SQL errors, reflected HTML) is left intact.
CSRF tokens are NOT redacted: clients legitimately echo them per request.
"""
from __future__ import annotations

import re
from typing import Any

MARKER = "[redacted]"

# Cookie names whose VALUE is a bearer credential for the session.
_SESSION_COOKIE_RE = re.compile(
    r"(?ix)(?P<name>PHPSESSID|JSESSIONID|sessionid?|connect\.sid|"
    r"auth(?:_token)?|access_token|id_token|refresh_token|session)"
    r"\s*=\s*(?P<value>[^;\s,]+)"
)

# Authorization header lines: scheme + token. Whole value (after optional
# scheme word) is redacted; the scheme (Bearer/Basic/Digest) is kept.
_AUTH_HEADER_RE = re.compile(
    r"(?ix)(?P<name>Authorization|Proxy-Authorization)\s*:\s*"
    r"(?P<value>(?:Bearer|Basic|Digest)\s+\S+|\S+)"
)

# key=value pairs in query strings / bodies whose VALUE is a credential.
_SECRET_PAIR_RE = re.compile(
    r"(?ix)(?P<key>password|passwd|pwd|secret|client_secret|api[_-]?key|apikey|"
    r"access[_-]?token|refresh[_-]?token|auth[_-]?token|session[_-]?id|"
    r"authorization|creds?|credentials)\s*=\s*"
    r"(?P<value>[^&\s;]+)"
)


def _redact_match(match: "re.Match[str]") -> str:
    """Rebuild the match replacing the ``value`` capture with [redacted].

    A short auth scheme (Bearer/Basic/Digest) prefix is kept so the reader still
    sees the credential type without the secret itself.
    """
    start, end = match.span("value")
    value = match.group("value")
    prefix = ""
    scheme = re.match(r"(?i)^(Bearer|Basic|Digest)\s+", value)
    if scheme:
        prefix = scheme.group(0)
    text = match.group(0)
    return text[: start - match.start()] + prefix + MARKER + text[end - match.start() :]


def redact_secrets(text: str) -> str:
    """Replace session credentials appearing in ``text`` with ``[redacted]``.

    Covers session cookies, Authorization/Proxy-Authorization header values and
    sensitive ``key=value`` pairs. Everything else is preserved verbatim.
    """
    if not text:
        return text
    out = _SESSION_COOKIE_RE.sub(_redact_match, text)
    out = _AUTH_HEADER_RE.sub(_redact_match, out)
    return _SECRET_PAIR_RE.sub(_redact_match, out)


def redact_request_data(rd: Any) -> Any:
    """Return a deep copy of request_data with credentials redacted.

    The original structure is never mutated; dicts/headers are copied so the
    underlying finding stays intact.
    """
    if rd is None:
        return None
    if isinstance(rd, dict):
        return {str(k): _redact_value(k, v) for k, v in rd.items()}
    if isinstance(rd, list):
        return [redact_request_data(item) for item in rd]
    if isinstance(rd, str):
        return redact_secrets(rd)
    return rd


# Header/value keys that are credentials outright: their entire value is a secret.
_HEADER_SECRET_KEYS = {
    "cookie", "set-cookie",
    "authorization", "proxy-authorization",
    "x-api-key", "api-key",
}

_STRUCTURED_SECRET_KEYS = {
    "password", "passwd", "pwd", "secret", "client_secret", "clientsecret",
    "api_key", "apikey", "access_token", "accesstoken", "refresh_token",
    "auth_token", "authtoken", "session_id", "sessionid", "authorization",
    "credentials", "credential", "token",
}


def _redact_value(key: Any, value: Any) -> Any:
    key_l = str(key).lower()
    if isinstance(value, dict):
        return {str(k): _redact_value(k, v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_request_data(item) for item in value]
    if isinstance(value, str):
        if key_l in _STRUCTURED_SECRET_KEYS:
            return MARKER
        if key_l in _HEADER_SECRET_KEYS:
            return redact_secrets(value)
        return redact_secrets(value)
    return value
