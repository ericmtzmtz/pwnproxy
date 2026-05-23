import asyncio
import time
from dataclasses import dataclass, field
from typing import AsyncIterator, Optional

import httpx


@dataclass
class IntruderResult:
    request_id: int
    payload: str
    status_code: int
    response_length: int
    timing_ms: float
    error: Optional[str] = None


class IntruderEngine:
    """Executes fuzzing requests with concurrency control."""

    def __init__(self, concurrency: int = 10):
        self._concurrency = concurrency
        self._semaphore = asyncio.Semaphore(concurrency)
        self._client: Optional[httpx.AsyncClient] = None
        self._request_id = 0

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(verify=False, timeout=30.0)
        return self._client

    async def execute(
        self,
        request_generator: AsyncIterator[tuple[str, str]],
        total: int,
    ) -> AsyncIterator[IntruderResult]:
        """Execute fuzzing requests, yielding results as they complete."""
        self._request_id = 0
        client = await self._get_client()

        async def _send_one(payload: str, raw_request: str) -> IntruderResult:
            async with self._semaphore:
                self._request_id += 1
                rid = self._request_id
                start = time.monotonic()
                try:
                    parsed = _parse_raw_from_template(raw_request)
                    response = await client.request(
                        method=parsed["method"],
                        url=parsed["url"],
                        headers=parsed["headers"],
                        content=parsed["body"],
                    )
                    elapsed = (time.monotonic() - start) * 1000
                    return IntruderResult(
                        request_id=rid,
                        payload=payload,
                        status_code=response.status_code,
                        response_length=len(response.content),
                        timing_ms=round(elapsed, 1),
                    )
                except Exception as exc:
                    elapsed = (time.monotonic() - start) * 1000
                    return IntruderResult(
                        request_id=rid,
                        payload=payload,
                        status_code=0,
                        response_length=0,
                        timing_ms=round(elapsed, 1),
                        error=str(exc),
                    )

        tasks = []
        async for payload, raw_request in request_generator:
            tasks.append(asyncio.create_task(_send_one(payload, raw_request)))

        for task in asyncio.as_completed(tasks):
            yield await task

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None


def _parse_raw_from_template(raw: str) -> dict:
    """Minimal parser to extract method, URL, headers, body from template."""
    lines = raw.splitlines()
    if not lines:
        raise ValueError("Empty request")

    request_line = lines[0].strip()
    parts = request_line.split(" ", 2)
    method = parts[0]
    path = parts[1] if len(parts) > 1 else "/"

    headers: dict[str, str] = {}
    body_lines: list[str] = []
    in_body = False
    for line in lines[1:]:
        if not in_body:
            if line == "" or line == "\r":
                in_body = True
                continue
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip()] = v.strip()
        else:
            body_lines.append(line)

    host = headers.get("Host", "localhost")
    scheme = headers.get("X-Forwarded-Proto", "https")
    url = f"{scheme}://{host}{path}"
    body = "\n".join(body_lines) if body_lines else ""

    return {
        "method": method,
        "url": url,
        "headers": headers,
        "body": body.encode("utf-8") if body else None,
    }
