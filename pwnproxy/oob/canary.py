"""Canary token generation and registry for OOB callbacks."""
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class CanaryToken:
    """A unique canary token for tracking OOB callbacks."""
    token: str
    scan_id: str
    created_at: float = field(default_factory=time.time)
    callback_received: bool = False
    callback_ip: Optional[str] = None
    callback_headers: dict = field(default_factory=dict)
    callback_at: Optional[float] = None
    
    @property
    def is_expired(self) -> bool:
        """Check if canary has expired (default: 60 seconds)."""
        return time.time() - self.created_at > 60


class CanaryRegistry:
    """Registry for managing canary tokens.
    
    Each scan gets a unique canary token that can be embedded in payloads.
    When the target makes an outbound request to the callback server,
    the canary is marked as confirmed.
    """
    
    def __init__(self):
        self._tokens: dict[str, CanaryToken] = {}
    
    def create(self, scan_id: str) -> CanaryToken:
        """Create a new canary token for a scan.
        
        Args:
            scan_id: Unique identifier for the scan
            
        Returns:
            New CanaryToken instance
        """
        # Generate unique token (16 hex chars)
        token = secrets.token_hex(8)
        canary = CanaryToken(token=token, scan_id=scan_id)
        self._tokens[token] = canary
        logger.debug("Created canary token %s for scan %s", token, scan_id)
        return canary
    
    def get(self, token: str) -> Optional[CanaryToken]:
        """Get a canary token by its value.
        
        Args:
            token: The canary token string
            
        Returns:
            CanaryToken if found, None otherwise
        """
        return self._tokens.get(token)
    
    def mark_callback(
        self,
        token: str,
        ip: str,
        headers: Optional[dict] = None,
    ) -> bool:
        """Mark a canary as having received a callback.
        
        Args:
            token: The canary token string
            ip: IP address of the callback source
            headers: HTTP headers from the callback request
            
        Returns:
            True if canary was found and marked, False otherwise
        """
        canary = self._tokens.get(token)
        if canary is None:
            logger.warning("Callback for unknown canary token: %s", token)
            return False
        
        if canary.is_expired:
            logger.warning("Callback for expired canary token: %s", token)
            return False
        
        canary.callback_received = True
        canary.callback_ip = ip
        canary.callback_headers = headers or {}
        canary.callback_at = time.time()
        logger.info(
            "Canary %s confirmed via callback from %s",
            token,
            ip,
        )
        return True
    
    def cleanup_expired(self) -> int:
        """Remove expired canary tokens.
        
        Returns:
            Number of tokens removed
        """
        expired = [
            token for token, canary in self._tokens.items()
            if canary.is_expired
        ]
        for token in expired:
            del self._tokens[token]
        if expired:
            logger.debug("Cleaned up %d expired canary tokens", len(expired))
        return len(expired)
    
    def list_active(self) -> list[CanaryToken]:
        """List all active (non-expired) canary tokens."""
        return [
            canary for canary in self._tokens.values()
            if not canary.is_expired
        ]
    
    def __len__(self) -> int:
        return len(self._tokens)


# Global registry instance
_registry: Optional[CanaryRegistry] = None


def get_registry() -> CanaryRegistry:
    """Get the global canary registry instance."""
    global _registry
    if _registry is None:
        _registry = CanaryRegistry()
    return _registry
