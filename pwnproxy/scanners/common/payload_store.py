"""Persistent payload store for second-order vulnerability detection.

Stores injected payloads keyed by (url, param, session) so the trigger
mechanism can re-request URLs to check for stored payloads appearing
in subsequent responses.
"""
import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class StoredPayload:
    """A payload that was injected and may trigger second-order effects."""
    url: str
    param_name: str
    param_location: str
    payload: str
    session_id: str = ""
    injected_at: float = field(default_factory=time.time)
    triggered: bool = False
    triggered_at: Optional[float] = None
    trigger_result: Optional[str] = None


class PayloadStore:
    """Stores injected payloads for later second-order detection.
    
    Payloads are stored in-memory keyed by URL. A background task
    periodically re-requests stored URLs to check if payloads appear
    in different responses (indicating stored/second-order vulns).
    """
    
    MAX_STORED = 1000
    
    def __init__(self):
        self._payloads: dict[str, list[StoredPayload]] = {}
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._interval = 60  # seconds
    
    def store(
        self,
        url: str,
        param_name: str,
        param_location: str,
        payload: str,
        session_id: str = "",
    ) -> None:
        """Store a payload for later triggering.
        
        Args:
            url: The URL where payload was injected
            param_name: The parameter name
            param_location: Where the parameter is (query/body/header)
            payload: The injected payload value
            session_id: Session identifier
        """
        url_key = self._normalize_url(url)
        stored = StoredPayload(
            url=url,
            param_name=param_name,
            param_location=param_location,
            payload=payload,
            session_id=session_id,
        )
        
        if url_key not in self._payloads:
            self._payloads[url_key] = []
        
        self._payloads[url_key].append(stored)
        
        # Trim if too many
        total = sum(len(v) for v in self._payloads.values())
        if total > self.MAX_STORED:
            # Remove oldest entries
            all_payloads = []
            for plist in self._payloads.values():
                all_payloads.extend(plist)
            all_payloads.sort(key=lambda p: p.injected_at)
            # Remove oldest half
            to_remove = all_payloads[:len(all_payloads) // 2]
            for p in to_remove:
                url_key = self._normalize_url(p.url)
                if p in self._payloads.get(url_key, []):
                    self._payloads[url_key].remove(p)
        
        logger.debug(
            "Stored payload for %s param=%s (%d total)",
            url,
            param_name,
            total,
        )
    
    def get_payloads(self, url: str) -> list[StoredPayload]:
        """Get all stored payloads for a URL."""
        url_key = self._normalize_url(url)
        return self._payloads.get(url_key, [])
    
    def get_all_untriggered(self) -> list[StoredPayload]:
        """Get all payloads that haven't been triggered yet."""
        result = []
        for plist in self._payloads.values():
            for p in plist:
                if not p.triggered:
                    result.append(p)
        return result
    
    def mark_triggered(self, url: str, payload: str, result: str = "") -> None:
        """Mark a payload as triggered with result."""
        url_key = self._normalize_url(url)
        for p in self._payloads.get(url_key, []):
            if p.payload == payload and not p.triggered:
                p.triggered = True
                p.triggered_at = time.time()
                p.trigger_result = result
                break
    
    def stats(self) -> dict:
        """Get store statistics."""
        total = sum(len(v) for v in self._payloads.values())
        triggered = sum(
            1 for plist in self._payloads.values()
            for p in plist if p.triggered
        )
        return {
            "total_stored": total,
            "triggered": triggered,
            "pending": total - triggered,
            "urls_tracked": len(self._payloads),
        }
    
    def clear(self) -> None:
        """Clear all stored payloads."""
        self._payloads.clear()
    
    @staticmethod
    def _normalize_url(url: str) -> str:
        """Normalize URL for key comparison."""
        # Remove trailing slash and hash
        url = url.split("#")[0]
        return url.rstrip("/")
    
    def __len__(self) -> int:
        return sum(len(v) for v in self._payloads.values())


# Global store instance
_store: Optional[PayloadStore] = None


def get_store() -> PayloadStore:
    """Get the global payload store instance."""
    global _store
    if _store is None:
        _store = PayloadStore()
    return _store
