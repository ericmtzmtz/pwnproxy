import logging
from collections.abc import Callable

from pwnproxy.services.session.manager import ScopeConfig

logger = logging.getLogger(__name__)

class FlowFilter:
    def __init__(
        self,
        scope_config: ScopeConfig,
        scope_provider: Callable[[], ScopeConfig] | None = None,
    ):
        """Filter that answers the capture and the active-scan questions.

        Args:
            scope_config: Scope in force when the filter is built.
            scope_provider: Optional live source (e.g.
                ``SessionManager.get_scope``). When given, every decision
                re-reads the scope from it, because ``update_scope``/``load``
                *replace* the ``ScopeConfig`` instance and a holder created once
                would keep answering with the old rules. ``set_scope`` remains
                the explicit hot-swap for holders without a provider.
        """
        self._scope = scope_config
        self._scope_provider = scope_provider
        self._capture_enabled = True

    def _current_scope(self) -> ScopeConfig:
        """The scope in force right now (see ``scope_provider``)."""
        if self._scope_provider is not None:
            self._scope = self._scope_provider()
        return self._scope

    def allow(self, url: str) -> bool:
        if not self._capture_enabled:
            return False
        return self._current_scope().is_in_scope(url)

    def allow_active_scan(self, url: str) -> bool:
        """Whether ``url`` may be handed to the active scanners.

        Two questions in one place: the scope must be *on* with at least one
        include rule (:meth:`ScopeConfig.active_scan_allowed`) **and** the URL
        must be inside it. Capture and history keep using :meth:`allow`, which
        is unchanged — with the scope off everything is still captured and
        stored, it just never reaches a plugin.

        Args:
            url: Absolute URL of the captured flow.

        Returns:
            ``True`` when the flow may be published on the ``flow``/``done``
            channels the plugins consume.
        """
        scope = self._current_scope()
        return scope.active_scan_allowed() and scope.is_in_scope(url)

    def active_scan_blocked_reason(self) -> str | None:
        """Why active scanning is blocked, in words, or ``None`` (see above)."""
        return self._current_scope().active_scan_blocked_reason()

    def set_scope(self, scope_config) -> None:
        """Hot-swap the scope config without rebuilding the filter.

        Used by the proxy worker on scope reload so the live relay and storage
        addons (which hold a stable reference to this instance) pick up the new
        scope immediately. Ignored while a ``scope_provider`` is wired: there the
        owner of the scope is the source of truth.
        """
        self._scope = scope_config

    @property
    def capture_enabled(self) -> bool:
        return self._capture_enabled

    def set_capture_enabled(self, enabled: bool) -> None:
        old = self._capture_enabled
        self._capture_enabled = enabled
        if old != enabled:
            logger.info(f"Capture {'enabled' if enabled else 'disabled'}")
