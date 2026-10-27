import base64
import json as json_mod
import logging
from datetime import UTC, datetime

logger = logging.getLogger(__name__)


def _b64url_decode(segment: str) -> bytes:
    """Decode a base64url JWT segment, tolerating missing/extra padding.

    JWT segments are unpadded base64url per RFC 7515. PyJWT >= 2.15 rejects
    malformed signature padding even with ``verify_signature=False``, which
    would break token *inspection* on a proxy. We decode the header/payload
    ourselves so inspection never depends on the verifier's strictness.
    """
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def jwt_decode(token_value: str) -> dict:
    """Decode a JWT for inspection, without verifying its signature.

    Returns a dict with ``header``, ``payload`` and a ``status`` of
    ``valid`` / ``expired`` / ``invalid_signature``. The signature is never
    validated: this inspects tokens seen in proxy traffic, so a truncated or
    corrupt signature must not hide an otherwise readable header/payload.
    """
    result = {
        "header": None,
        "payload": None,
        "status": "unknown",
    }

    parts = token_value.split(".")
    if len(parts) < 2:
        logger.debug("JWT decode failed: expected at least 2 segments, got %d", len(parts))
        result["status"] = "invalid_signature"
        return result

    try:
        result["header"] = json_mod.loads(_b64url_decode(parts[0]).decode("utf-8"))
        result["payload"] = json_mod.loads(_b64url_decode(parts[1]).decode("utf-8"))
    except Exception as e:
        logger.debug(f"JWT decode failed: {e}")
        result["status"] = "invalid_signature"
        return result

    exp = result["payload"].get("exp") if isinstance(result["payload"], dict) else None
    if exp is not None:
        try:
            exp_dt = datetime.fromtimestamp(exp, tz=UTC)
            now = datetime.now(UTC)
            result["status"] = "valid" if now < exp_dt else "expired"
            result["expires_at"] = exp_dt
        except Exception:
            result["status"] = "unknown"
    else:
        result["status"] = "valid"

    return result
