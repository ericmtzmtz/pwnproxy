import logging
from typing import Optional
from pwnproxy.services.session.manager import ScopeConfig

logger = logging.getLogger(__name__)

class FlowFilter:
    def __init__(self, scope_config: ScopeConfig):
        self._scope = scope_config
        self._capture_enabled = True

    def allow(self, url: str) -> bool:
        if not self._capture_enabled:
            return False
        return self._scope.is_in_scope(url)

    @property
    def capture_enabled(self) -> bool:
        return self._capture_enabled

    def set_capture_enabled(self, enabled: bool) -> None:
        old = self._capture_enabled
        self._capture_enabled = enabled
        if old != enabled:
            logger.info(f"Capture {'enabled' if enabled else 'disabled'}")
