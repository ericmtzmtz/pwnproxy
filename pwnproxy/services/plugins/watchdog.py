import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

DISABLE_THRESHOLD = 3


class PluginWatchdog:
    def __init__(self, threshold: int = DISABLE_THRESHOLD):
        self._threshold = threshold
        self._failures: dict[str, int] = defaultdict(int)
        self._disabled: set[str] = set()

    def report_failure(self, plugin_name: str, reason: str) -> None:
        self._failures[plugin_name] += 1
        count = self._failures[plugin_name]
        logger.warning("Plugin %s failed (%d/%d): %s", plugin_name, count, self._threshold, reason)
        if count >= self._threshold:
            self._disabled.add(plugin_name)
            logger.error("Plugin %s auto-disabled after %d consecutive failures", plugin_name, count)

    def report_success(self, plugin_name: str) -> None:
        self._failures[plugin_name] = 0

    def is_disabled(self, plugin_name: str) -> bool:
        return plugin_name in self._disabled

    def enable(self, plugin_name: str) -> None:
        self._disabled.discard(plugin_name)
        self._failures[plugin_name] = 0
        logger.info("Plugin %s re-enabled", plugin_name)

    def disable(self, plugin_name: str) -> None:
        self._disabled.add(plugin_name)
        logger.info("Plugin %s manually disabled", plugin_name)

    def stats(self) -> dict[str, dict]:
        return {
            "failures": dict(self._failures),
            "disabled": list(self._disabled),
            "threshold": self._threshold,
        }
