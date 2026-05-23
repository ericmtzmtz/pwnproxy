from typing import Optional

import httpx


class RepeaterEngine:
    """Replays parsed HTTP requests using httpx."""

    def __init__(self) -> None:
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(verify=False, timeout=30.0)
        return self._client

    async def send(self, parsed: dict) -> httpx.Response:
        """Send a parsed request and return the response.

        Args:
            parsed: dict with keys method, path, headers, body.
                    The Host header determines the base URL.
        """
        client = await self._get_client()
        headers = parsed.get("headers", {})
        host = headers.get("Host", "localhost")
        scheme = headers.get("X-Forwarded-Proto", "https")
        path = parsed.get("path", "/")
        url = f"{scheme}://{host}{path}"
        method = parsed.get("method", "GET")
        body = parsed.get("body", "")

        response = await client.request(
            method=method,
            url=url,
            headers=headers,
            content=body.encode("utf-8") if body else None,
        )
        return response

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
