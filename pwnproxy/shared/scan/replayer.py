import json
import logging
import asyncio
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from pwnproxy.shared.scan.evasion import EvasionLevel, apply_evasion
from pwnproxy.shared.scan.params import InjectionPoint, _header

logger = logging.getLogger(__name__)


class RequestReplayer:
    def __init__(self):
        self._client = httpx.AsyncClient(verify=False, follow_redirects=False, timeout=httpx.Timeout(30.0))
        self._global_semaphore = asyncio.Semaphore(5)
        self._host_semaphores: dict[str, asyncio.Semaphore] = {}
        self._host_lock = asyncio.Lock()

    def _build_request(
        self,
        point: InjectionPoint,
        payload: str,
        evasion_level: str = "none",
    ) -> httpx.Request:
        """Build an HTTP request with the payload injected.

        Protected hook — subclasses override this for specialised mutation
        (e.g. ``XxeReplayer`` mutates the XML body instead of parameters).

        Base implementation: inject *payload* as the parameter value using
        ``point.inject()``, then build the request with ``build_request()``.
        """
        method = point.method.upper()
        headers = dict(point.original_headers)
        evaded = apply_evasion(payload, EvasionLevel(evasion_level) if isinstance(evasion_level, str) else evasion_level)
        if point.location == "query":
            url = _inject_query(point.url, point.name, evaded)
            body = point.original_body.encode() if point.original_body else None
            if body and _header(headers, "content-type"):
                pass
            elif body:
                headers.pop("content-length", None)
            return httpx.Request(method, url, headers=headers, content=body)
        elif point.location == "body":
            ct = _header(headers, "content-type")
            if "application/x-www-form-urlencoded" in ct:
                body = _inject_form_body(point.original_body or "", point.name, evaded)
            elif "application/json" in ct:
                body = _inject_json_body(point.original_body or "", point.name, evaded)
            else:
                body = point.original_body.encode() if point.original_body else None
            headers.pop("content-length", None)
            return httpx.Request(method, point.url, headers=headers, content=body)
        elif point.location == "cookie":
            cookies = _inject_cookie(headers.get("cookie", ""), point.name, evaded)
            headers["cookie"] = cookies
            body = point.original_body.encode() if point.original_body else None
            return httpx.Request(method, point.url, headers=headers, content=body)
        elif point.location == "header":
            headers[point.name] = evaded
            body = point.original_body.encode() if point.original_body else None
            return httpx.Request(method, point.url, headers=headers, content=body)
        else:
            raise ValueError(f"Unsupported injection location: {point.location}")

    async def replay(
        self,
        point: InjectionPoint,
        payload: str,
        timeout: float = 5.0,
        evasion_level: str | EvasionLevel = EvasionLevel.NONE,
    ) -> Optional[httpx.Response]:
        """Send the request with the injection payload.

        Uses ``self._build_request()`` so subclasses can override
        request construction without touching the send logic.
        """
        return await self._send(
            point,
            payload,
            timeout=timeout,
            evasion_level=evasion_level,
        )

    def build_payload_request(
        self,
        point: InjectionPoint,
        payload: str,
        evasion_level: str | EvasionLevel = EvasionLevel.NONE,
    ) -> httpx.Request:
        """Build (but do not send) the payload request — same as replay sends.

        Lets callers serialize the exact request that triggered a finding
        (method, injected URL, headers, body) for persistence/validation.
        """
        return self._build_request(point, payload, evasion_level)

    async def send_clean(self, point: InjectionPoint, timeout: float = 10.0) -> Optional[httpx.Response]:
        headers = dict(point.original_headers)
        body = point.original_body.encode() if point.original_body else None
        try:
            return await self._client.request(
                point.method.upper(), point.url,
                headers=headers, content=body, timeout=timeout,
            )
        except Exception as e:
            logger.debug(f"Clean request failed: {e}")
            return None

    async def _send(
        self,
        point: InjectionPoint,
        payload: str,
        timeout: float,
        evasion_level: str = "none",
    ) -> Optional[httpx.Response]:
        """Build and send the request with rate limiting, returning response or None on failure."""
        async with self._global_semaphore:
            async with self._host_lock:
                if point.host not in self._host_semaphores:
                    self._host_semaphores[point.host] = asyncio.Semaphore(2)
            async with self._host_semaphores[point.host]:
                await asyncio.sleep(0.1)  # inter-request delay
                try:
                    request = self._build_request(point, payload, evasion_level)
                    resp = await self._client.send(request)
                    return resp
                except Exception as exc:
                    logger.debug("Replayer error for %s: %s", point.key, exc)
                    return None

    async def close(self) -> None:
        await self._client.aclose()


def _inject_query(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _inject_form_body(body: str, param: str, payload: str) -> bytes:
    params = parse_qs(body, keep_blank_values=True)
    params[param] = [payload]
    new_body = urlencode(params, doseq=True)
    return new_body.encode()


def _inject_json_body(body: str, param: str, payload: str) -> bytes:
    data = json.loads(body)
    keys = param.split(".")
    d = data
    for k in keys[:-1]:
        if isinstance(d, dict):
            d = d.get(k, {})
        else:
            return body.encode()
    if isinstance(d, dict):
        d[keys[-1]] = _coerce_type(payload, d.get(keys[-1]))
    return json.dumps(data).encode()


def _coerce_type(payload: str, original) -> object:
    if isinstance(original, bool):
        return payload.lower() in ("true", "false", "1", "0")
    if isinstance(original, int):
        try:
            return int(payload)
        except ValueError:
            return payload
    if isinstance(original, float):
        try:
            return float(payload)
        except ValueError:
            return payload
    return payload


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
def _serialize_request(req: httpx.Request) -> dict:
    """Serialize an httpx.Request into the finding request_data shape.

    Absolute URL with payload injected, headers as sent, body as str or None.
    """
    headers = dict(req.headers)
    body = req.content.decode("utf-8", "replace") if req.content else None
    return {
        "method": req.method.upper(),
        "url": str(req.url),
        "headers": headers,
        "body": body,
    }
