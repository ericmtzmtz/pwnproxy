import logging
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from pwnproxy.plugins.scanners.xss.models import XssCanary
from pwnproxy.plugins.scanners.xss.storage import XssFindingStorage

logger = logging.getLogger(__name__)


@dataclass
class CanaryMatch:
    canary_value: str
    canary_id: int
    source_url: str
    param_name: str
    param_location: str
    found_url: str


class CanaryStore:
    def __init__(self, storage: XssFindingStorage):
        self._storage = storage
        self._active: dict[str, XssCanary] = {}

    def generate(self) -> str:
        hex_val = secrets.token_hex(4)
        return f"pwnxss-{hex_val}"

    async def store(self, canary_value: str, source_url: str, param_name: str, param_location: str) -> None:
        now = datetime.now()
        record = XssCanary(
            canary_value=canary_value,
            source_url=source_url,
            param_name=param_name,
            param_location=param_location,
            injected_at=now,
        )
        await self._storage.save_canary(record)
        self._active[canary_value] = record

    async def scan_response(self, body: str, response_url: str) -> list[CanaryMatch]:
        if not body or not self._active:
            return []
        matches: list[CanaryMatch] = []
        for canary_value, record in list(self._active.items()):
            if canary_value in body:
                matches.append(CanaryMatch(
                    canary_value=canary_value,
                    canary_id=record.id,
                    source_url=record.source_url,
                    param_name=record.param_name,
                    param_location=record.param_location,
                    found_url=response_url,
                ))
                await self._storage.mark_canary_found(record.id, response_url)
                del self._active[canary_value]
        return matches

    async def cleanup(self, max_age_hours: int = 24) -> int:
        count = await self._storage.cleanup_old_canaries(max_age_hours)
        now = datetime.now()
        cutoff = now.timestamp() - max_age_hours * 3600
        expired = [
            k for k, v in self._active.items()
            if v.injected_at.timestamp() < cutoff
        ]
        for k in expired:
            del self._active[k]
        return count + len(expired)

    async def load_active(self) -> None:
        canaries = await self._storage.get_active_canaries()
        self._active = {c.canary_value: c for c in canaries}
