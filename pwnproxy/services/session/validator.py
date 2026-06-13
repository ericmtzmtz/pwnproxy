import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


def jwt_decode(token_value: str) -> dict:
    import jwt as pyjwt

    result = {
        "header": None,
        "payload": None,
        "status": "unknown",
    }

    try:
        unverified = pyjwt.decode(
            token_value,
            options={"verify_signature": False},
            algorithms=["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
        )
        result["payload"] = unverified
    except Exception as e:
        logger.debug(f"JWT payload decode failed: {e}")
        result["status"] = "invalid_signature"
        return result

    try:
        import json as json_mod
        import base64

        parts = token_value.split(".")
        header_json = base64.urlsafe_b64decode(parts[0] + "==").decode("utf-8")
        result["header"] = json_mod.loads(header_json)
    except Exception as e:
        logger.debug(f"JWT header decode failed: {e}")

    exp = result.get("payload", {}).get("exp")
    if exp is not None:
        try:
            exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)
            now = datetime.now(timezone.utc)
            result["status"] = "valid" if now < exp_dt else "expired"
            result["expires_at"] = exp_dt
        except Exception:
            result["status"] = "unknown"
    else:
        result["status"] = "valid"

    return result
