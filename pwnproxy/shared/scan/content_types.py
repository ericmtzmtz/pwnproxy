"""Content-type / body helpers shared by scan stages.

A detector that looks for *text* output in a response (OS command output,
SQL errors, file contents) can only work when the body is text. Bodies of
binary documents decoded as text are noise: a PDF, for instance, decodes to
a stream of ``obj`` / ``endobj`` / ``stream`` keywords that look like page
text and can trip line-based signatures.

The helpers here are pure (no I/O, no httpx import) so they are trivially
unit-testable; :func:`response_is_textual` adapts any response-like object
(httpx.Response or a fake) to them.
"""

from __future__ import annotations

# Declared MIME types that can never carry textual command/file output.
BINARY_MIME_TYPES = frozenset({
    "application/pdf",
    "application/octet-stream",
    "application/zip",
    "application/x-zip-compressed",
    "application/gzip",
    "application/x-gzip",
    "application/x-tar",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
    "application/vnd.rar",
    "application/x-bzip2",
    "application/x-xz",
    "application/msword",
    "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.ms-fontobject",
    "application/wasm",
    "application/x-protobuf",
    "application/x-shockwave-flash",
})

# Families that are binary whatever the subtype (image/png, audio/mpeg, ...).
BINARY_MIME_PREFIXES = ("image/", "audio/", "video/", "font/", "model/")

# Declared types that are always text even though they are not ``text/*``.
TEXTUAL_MIME_TYPES = frozenset({
    "application/json",
    "application/xml",
    "application/xhtml+xml",
    "application/javascript",
    "application/x-javascript",
    "application/ecmascript",
    "application/x-www-form-urlencoded",
    "application/graphql",
    "application/x-ndjson",
    "application/ld+json",
    "application/x-yaml",
    "application/yaml",
    "application/sql",
    "application/x-sh",
})

# Structured suffixes: application/problem+json, image/svg+xml, ...
TEXTUAL_MIME_SUFFIXES = ("+json", "+xml", "+yaml", "+text")


def mime_type(content_type: str | None) -> str:
    """Return the lowercased MIME type of a Content-Type header, without parameters.

    Args:
        content_type: Raw header value, e.g. ``"text/html; charset=utf-8"``.

    Returns:
        The bare type (``"text/html"``), or ``""`` when the header is missing
        or empty.
    """
    if not content_type:
        return ""
    return content_type.split(";", 1)[0].strip().lower()


def is_known_binary(content_type: str | None) -> bool:
    """True when the declared type is a binary document/image/archive family.

    Only a *declared* type is judged here: an unknown or missing header
    returns ``False`` so callers fall back to sniffing the body instead of
    assuming binary.

    Args:
        content_type: Raw Content-Type header value (may include parameters).

    Returns:
        ``True`` for PDF, archives, images, audio, video, fonts and other
        families that cannot contain textual command output. Textual types
        inside those families (``image/svg+xml``) are not binary.
    """
    mime = mime_type(content_type)
    if not mime:
        return False
    if mime in BINARY_MIME_TYPES:
        return True
    if is_textual_mime_type(mime):
        return False
    return mime.startswith(BINARY_MIME_PREFIXES)


def is_textual_mime_type(content_type: str | None) -> bool:
    """True when the declared type is textual (``text/*``, JSON, XML, JS, ...)."""
    mime = mime_type(content_type)
    if not mime:
        return False
    if mime.startswith("text/"):
        return True
    if mime in TEXTUAL_MIME_TYPES:
        return True
    return mime.endswith(TEXTUAL_MIME_SUFFIXES)


def is_decodable_text(body: bytes | str | None) -> bool:
    """True when a body can be read as text.

    Bytes must be strict UTF-8 without NUL bytes; a ``str`` must have no NUL
    bytes. ``None`` (body not captured) is *not* provably text → ``False``.

    Args:
        body: Raw bytes, already-decoded text, or ``None``.

    Returns:
        ``True`` when the body is decodable text.
    """
    if body is None:
        return False
    if isinstance(body, str):
        return "\x00" not in body
    if isinstance(body, (bytes, bytearray)):
        raw = bytes(body)
        if b"\x00" in raw:
            return False
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return True
    return False


def is_textual(content_type: str | None, body: bytes | str | None) -> bool:
    """Decide whether a response body can be compared against text signatures.

    A declared binary type wins over the body (a PDF with an ASCII-only body is
    still a PDF). A declared textual type wins too. Anything else — missing
    header, exotic ``application/x-foo`` — is decided by sniffing the body.

    Args:
        content_type: Raw Content-Type header value (may be ``None``/empty).
        body: Response body as bytes, str or ``None`` when not captured.

    Returns:
        ``True`` when the response is textual (or plausibly textual).
    """
    if is_known_binary(content_type):
        return False
    if is_textual_mime_type(content_type):
        return True
    return is_decodable_text(body)


def header_value(headers, name: str) -> str:
    """Case-insensitive header lookup that tolerates non-dict header objects.

    Args:
        headers: A mapping, ``httpx.Headers`` or any object exposing ``items()``.
        name: Lowercase header name to look for.

    Returns:
        The header value, or ``""`` when absent (or when ``headers`` is not a
        usable mapping).
    """
    if not headers:
        return ""
    try:
        items = list(headers.items())
    except (AttributeError, TypeError):
        return ""
    for key, value in items:
        if str(key).lower() == name:
            return "" if value is None else str(value)
    return ""


def response_is_textual(response) -> bool:
    """True when an httpx-like response can carry textual output.

    Reads only ``headers``, ``content`` and ``text`` so plain fakes work too.
    The content type is taken from the response headers; when it is missing or
    unknown the raw body is sniffed, and the decoded ``text`` is the last
    resort.

    Args:
        response: Any object with optional ``headers`` / ``content`` / ``text``.

    Returns:
        ``True`` when the response body is textual.
    """
    if response is None:
        return False
    content_type = header_value(getattr(response, "headers", None), "content-type")
    body = getattr(response, "content", None)
    if not isinstance(body, (bytes, bytearray, str)):
        body = getattr(response, "text", None)
        if not isinstance(body, str):
            body = None
    return is_textual(content_type, body)


__all__ = [
    "BINARY_MIME_PREFIXES",
    "BINARY_MIME_TYPES",
    "TEXTUAL_MIME_SUFFIXES",
    "TEXTUAL_MIME_TYPES",
    "header_value",
    "is_decodable_text",
    "is_known_binary",
    "is_textual",
    "is_textual_mime_type",
    "mime_type",
    "response_is_textual",
]
