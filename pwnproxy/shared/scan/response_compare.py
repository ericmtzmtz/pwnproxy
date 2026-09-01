"""Pure, HTTP-free helpers for comparing HTTP responses.

Used by boolean-based SQLi detection. The goal is to distinguish a TRUE
injection response from a FALSE one by *structure*, never by raw body
length alone (a page with a CSRF token, timestamp or random UUID differs
in length on every request regardless of injection).

All functions are pure (no I/O), so they are trivially unit-testable.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Optional

# UUIDs, e.g. 0f8fad5b-d9cb-469f-a165-70867728950e
_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
# 10-13 digit timestamps, e.g. 1785600000000
_TOKEN_RE = re.compile(r"(?<![0-9])[0-9]{10,13}(?![0-9])")
# session / csrf tokens of the form name=value with a long alnum payload
_SESSION_RE = re.compile(
    r"(?i)\b(session|sessionid|jsessionid|phpsessid|asp\.net_sessionid|csrf|_csrf|token|nonce|csrfmiddlewaretoken|state)"
    r"(=|:)"
    r"[0-9a-zA-Z_.\-+/=]{8,}"
)
_MULTI_WS_RE = re.compile(r"\s+")

DEFAULT_BLOCK = 512
# Above this structural similarity, two responses cannot be told apart.
SAME_THRESHOLD = 0.99
# Below this normalized-length ratio the responses differ structurally.
MIN_SAME_RATIO = 0.90


def normalize_body(body: str) -> str:
    """Strip dynamic noise (tokens, timestamps, UUIDs) and all whitespace.

    Removing whitespace entirely (rather than collapsing to one space) makes
    the fingerprint robust to pages whose only difference is repeated
    padding/line noise — the HTML/SVG structure is preserved by the tags.
    """
    if body is None:
        return ""
    s = _UUID_RE.sub("TOKEN", body)
    s = _TOKEN_RE.sub("TOKEN", s)
    s = _SESSION_RE.sub(r"\1=\2TOKEN", s)
    s = _MULTI_WS_RE.sub("", s)
    return s


def _block_hashes(s: str, block: int) -> list[str]:
    hashes: list[str] = []
    for i in range(0, max(1, len(s)), block):
        chunk = s[i : i + block]
        hashes.append(hashlib.sha1(chunk.encode("utf-8", "replace")).hexdigest())
    return hashes


@dataclass
class Fingerprint:
    """Structural fingerprint of an HTTP response."""

    status: int
    raw_len: int
    norm_len: int
    block_hashes: list[str] = field(default_factory=list)

    @classmethod
    def build(cls, status: int, body: str, block: int = DEFAULT_BLOCK) -> "Fingerprint":
        norm = normalize_body(body or "")
        return cls(
            status=status,
            raw_len=len(body or ""),
            norm_len=len(norm),
            block_hashes=_block_hashes(norm, block),
        )


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    union = a | b
    if not union:
        return 1.0
    return len(a & b) / len(union)


def similarity(fp_a: Fingerprint, fp_b: Fingerprint) -> float:
    """Structural similarity in [0,1]. Returns 0.0 if status codes differ."""
    if fp_a.status != fp_b.status:
        return 0.0
    return _jaccard(set(fp_a.block_hashes), set(fp_b.block_hashes))


def is_boolean_differentiable(
    fp_true: Fingerprint,
    fp_false: Fingerprint,
    same_threshold: float = SAME_THRESHOLD,
    min_same_ratio: float = MIN_SAME_RATIO,
) -> bool:
    """True when TRUE and FALSE responses differ structurally.

    A pair is *not* differentiable when their structural similarity is at
    or above ``same_threshold`` (functionally identical responses — the
    page didn't change shape, e.g. an escaped/inert injection). Otherwise
    it is differentiable when either signal points to a real difference:

    - block-hash Jaccard similarity drops below ``min_same_ratio``, or
    - the normalized-length ratio drops below ``min_same_ratio`` (guards
      against near-identical bodies that the block hash Jaccard still
      scores just under the threshold due to a single dynamic element).

    Note: never, ever drives a decision off raw length alone. ``raw_len``
    is retained only for diagnostics/evidence.
    """
    if fp_true.status != fp_false.status:
        return True

    sim = _jaccard(set(fp_true.block_hashes), set(fp_false.block_hashes))
    if sim >= same_threshold:
        return False

    if fp_true.norm_len and fp_false.norm_len:
        longer = max(fp_true.norm_len, fp_false.norm_len)
        shorter = min(fp_true.norm_len, fp_false.norm_len)
        if shorter / longer < min_same_ratio:
            return True

    return sim < min_same_ratio


def bool_pair_similarity(body_true: str, body_false: str) -> float:
    """Convenience: structural similarity of two raw response bodies (same status assumed)."""
    return _jaccard(
        set(_block_hashes(normalize_body(body_true or ""), DEFAULT_BLOCK)),
        set(_block_hashes(normalize_body(body_false or ""), DEFAULT_BLOCK)),
    )
