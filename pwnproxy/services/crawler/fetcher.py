"""Direct HTTP fetcher for the active crawler.

Provides an asyncio rate limiter (token pacing) and a ``Fetcher`` that
issues GET requests directly to the target (bypassing the proxy),
returning the raw response dict for re-publishing to ``traffic.db``.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 15.0
_MAX_RETRIES = 1
MAX_BODY_BYTES = 512 * 1024


class RateLimiter:
    """Simple token-pacing limiter: *rate* requests per second."""

    def __init__(self, rate: float) -> None:
        self._min_interval = 1.0 / max(rate, 0.1)
        self._last = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            wait = self._min_interval - (now - self._last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()


class Fetcher:
    """Direct-to-target HTTP fetcher with rate limiting."""

    def __init__(self, rate_limit: float = 10.0, verify: bool = False) -> None:
        self._limiter = RateLimiter(rate_limit)
        self._verify = verify
        self._client: Optional[httpx.AsyncClient] = None

    async def start(self) -> None:
        self._client = httpx.AsyncClient(
            verify=self._verify,
            follow_redirects=False,
            timeout=_DEFAULT_TIMEOUT,
        )

    async def stop(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def fetch(self, url: str) -> Optional[dict]:
        # existing fetch method unchanged
        """GET *url* and return a flow-like dict, or None on failure.

        Retries once on transient connection errors.
        """
        if self._client is None:
            raise RuntimeError("Fetcher not started")
        last_exc: Optional[Exception] = None
        for _ in range(1 + _MAX_RETRIES):
            await self._limiter.acquire()
            t0 = time.monotonic()
            try:
                resp = await self._client.get(url)
                elapsed = (time.monotonic() - t0) * 1000
                body_raw = resp.content or b""
                body = body_raw[:MAX_BODY_BYTES].decode("utf-8", errors="replace")
                return {
                    "method": "GET",
                    "url": str(resp.url),
                    "request_headers": {k: v for k, v in resp.request.headers.multi_items()},
                    "request_body": None,
                    "response_headers": dict(resp.headers.multi_items()),
                    "response_body": body,
                    "response_body_truncated": len(body_raw) > MAX_BODY_BYTES,
                    "status_code": resp.status_code,
                    "duration_ms": round(elapsed, 1),
                    "tls": str(resp.url).startswith("https"),
                }
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError) as exc:
                last_exc = exc
                logger.debug("fetch %s transient error: %s", url, exc)
                continue
            except Exception as exc:
                logger.warning("fetch %s permanent error: %s", url, exc)
                return None

    async def probe(self, url: str) -> tuple[int, int, str] | None:
        """GET *url* and return (status_code, content_length, content_type)."""
        if self._client is None:
            raise RuntimeError("Fetcher not started")
        last_exc: Optional[Exception] = None
        for _ in range(1 + _MAX_RETRIES):
            await self._limiter.acquire()
            try:
                resp = await self._client.get(url)
                content_len = len(resp.content or b"")
                content_type = ""
                for name, value in (resp.headers.items() if hasattr(resp.headers, "items") else []):
                    if (name or "").lower() == "content-type":
                        content_type = value or ""
                        break
                return (resp.status_code, content_len, content_type)
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError) as exc:
                last_exc = exc
                logger.debug("probe %s transient error: %s", url, exc)
                continue
            except Exception as exc:
                logger.warning("probe %s permanent error: %s", url, exc)
                return None
        logger.warning("probe %s failed after retries: %s", url, last_exc)
        return None

async def learn_baseline(fetcher: Fetcher, base_url: str, n: int = 3) -> set[tuple[int, int]]:
    """Probe N random non-existent paths and return set of (status, length) signatures.

    Uses random paths like '/__nonexistent_{randhex}' that are unlikely to exist.
    The returned set is used to filter soft-404 responses.
    """
    signatures: set[tuple[int, int]] = set()
    for _ in range(n):
        rand_path = f"/__nonexistent_{secrets.token_hex(8)}"
        url = base_url.rstrip('/') + rand_path
        result = await fetcher.probe(url)
        if result is not None:
            status, length, _ = result
            signatures.add((status, length))
    return signatures


async def fetch_robots(url: str, verify: bool = False) -> Optional[str]:
    """Fetch robots.txt from *url*'s origin. Returns body text or None."""
    try:
        parsed = urlparse(url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        async with httpx.AsyncClient(verify=verify, timeout=5.0) as client:
            resp = await client.get(robots_url)
            if resp.status_code == 200:
                return resp.text
    except Exception:
        logger.debug("robots.txt fetch failed for %s", url, exc_info=True)
    return None


def parse_robots_disallow(robots_text: str) -> list[str]:
    """Extract Disallow prefixes from a robots.txt body."""
    rules: list[str] = []
    if not robots_text:
        return rules
    for line in robots_text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                rules.append(path)
    return rules


def is_disallowed(url: str, disallow_paths: list[str]) -> bool:
    """Return True if *url*'s path matches any Disallow prefix."""
    parsed = urlparse(url)
    path = parsed.path or "/"
    for prefix in disallow_paths:
        if path.startswith(prefix):
            return True
    return False
