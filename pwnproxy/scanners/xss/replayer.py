import json
import logging
from typing import Optional
from urllib.parse import urlencode, urlparse, urlunparse

import httpx

from pwnproxy.scanners.common.params import InjectionPoint

logger = logging.getLogger(__name__)


class XssReplayer:
    def __init__(self):
        self._client = httpx.AsyncClient(verify=False, follow_redirects=False)

    async def replay(
        self, point: InjectionPoint, payload: str, timeout: float = 5.0
    ) -> Optional[httpx.Response]:
        method = point.method.upper()
        headers = dict(point.original_headers)

        try:
            if point.location == "query":
                url = _inject_query(point.url, point.name, payload)
                body = point.original_body.encode() if point.original_body else None
                if body and "content-type" in headers:
                    pass
                elif body:
                    headers.pop("content-length", None)
                return await self._client.request(
                    method, url, headers=headers, content=body, timeout=timeout
                )

            elif point.location == "body":
                ct = headers.get("content-type", "").lower()
                if "application/x-www-form-urlencoded" in ct:
                    body = _inject_form_body(point.original_body or "", point.name, payload)
                elif "application/json" in ct:
                    body = _inject_json_body(point.original_body or "", point.name, payload)
                else:
                    body = point.original_body.encode() if point.original_body else None
                headers.pop("content-length", None)
                return await self._client.request(
                    method, point.url, headers=headers, content=body, timeout=timeout
                )

            elif point.location == "cookie":
                cookies = _inject_cookie(headers.get("cookie", ""), point.name, payload)
                headers["cookie"] = cookies
                body = point.original_body.encode() if point.original_body else None
                return await self._client.request(
                    method, point.url, headers=headers, content=body, timeout=timeout
                )

            elif point.location == "header":
                headers[point.name] = payload
                body = point.original_body.encode() if point.original_body else None
                return await self._client.request(
                    method, point.url, headers=headers, content=body, timeout=timeout
                )

        except httpx.TimeoutException:
            logger.debug(f"Timeout for {point.url} ({point.name}={payload})")
            return None
        except Exception as e:
            logger.warning(f"Replay failed for {point.url}: {e}")
            return None

        return None

    async def close(self) -> None:
        await self._client.aclose()


def _inject_query(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    from urllib.parse import parse_qs
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _inject_form_body(body: str, param: str, payload: str) -> bytes:
    from urllib.parse import parse_qs
    params = parse_qs(body, keep_blank_values=True)
    params[param] = [payload]
    new_body = urlencode(params, doseq=True)
    return new_body.encode()


def _inject_json_body(body: str, param: str, payload: str) -> bytes:
    import json as json_mod
    data = json_mod.loads(body)
    keys = param.split(".")
    d = data
    for k in keys[:-1]:
        if isinstance(d, dict):
            d = d.get(k, {})
        else:
            return body.encode()
    if isinstance(d, dict):
        d[keys[-1]] = payload
    return json_mod.dumps(data).encode()


def _inject_cookie(cookie_header: str, param: str, payload: str) -> str:
    parts = []
    for pair in cookie_header.split(";"):
        pair = pair.strip()
        if "=" in pair:
            name, _, val = pair.partition("=")
            if name.strip() == param:
                parts.append(f"{name.strip()}={payload}")
            else:
                parts.append(pair)
        else:
            parts.append(pair)
    return "; ".join(parts)
