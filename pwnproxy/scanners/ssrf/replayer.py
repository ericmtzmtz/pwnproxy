import logging
from typing import Optional

import httpx

from pwnproxy.scanners.common.params import InjectionPoint
from pwnproxy.scanners.lfi.replayer import (
    _inject_cookie,
    _inject_form_body,
    _inject_json_body,
    _inject_query,
)

logger = logging.getLogger(__name__)


class SsrfReplayer:
    def __init__(self):
        self._client = httpx.AsyncClient(verify=False, follow_redirects=False)

    async def inject(self, point: InjectionPoint, payload: str) -> Optional[httpx.Response]:
        method = point.method.upper()
        headers = dict(point.original_headers)

        try:
            if point.location == "query":
                url = _inject_query(point.url, point.name, payload)
                body = point.original_body.encode() if point.original_body else None
                return await self._client.request(method, url, headers=headers, content=body, timeout=5.0)

            elif point.location == "body":
                ct = headers.get("content-type", "").lower()
                if "application/x-www-form-urlencoded" in ct:
                    body = _inject_form_body(point.original_body or "", point.name, payload)
                elif "application/json" in ct:
                    body = _inject_json_body(point.original_body or "", point.name, payload)
                else:
                    return None
                headers.pop("content-length", None)
                return await self._client.request(method, point.url, headers=headers, content=body, timeout=5.0)

            elif point.location == "cookie":
                cookies = _inject_cookie(headers.get("cookie", ""), point.name, payload)
                headers["cookie"] = cookies
                body = point.original_body.encode() if point.original_body else None
                return await self._client.request(method, point.url, headers=headers, content=body, timeout=5.0)

            elif point.location == "header":
                headers[point.name] = payload
                body = point.original_body.encode() if point.original_body else None
                return await self._client.request(method, point.url, headers=headers, content=body, timeout=5.0)

        except httpx.TimeoutException:
            logger.debug(f"Timeout for SSRF {point.url} ({point.name}={payload})")
            return None
        except Exception as e:
            logger.warning(f"SSRF replay failed for {point.url}: {e}")
            return None

        return None

    async def close(self) -> None:
        await self._client.aclose()
