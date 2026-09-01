import logging
import mitmproxy.http
from mitmproxy import flow

from pwnproxy.shared.hooks import HookBus
from pwnproxy.shared.models import Flow

logger = logging.getLogger(__name__)


class HookRelayAddon:
    """Mitmproxy addon that forwards events to the HookBus."""

    def __init__(self, hook_bus: HookBus, flow_filter=None):
        self.hook_bus = hook_bus
        self._flow_filter = flow_filter

    def _in_scope(self, url: str) -> bool:
        if self._flow_filter is None:
            return True
        return self._flow_filter.allow(url)

    def request(self, f: mitmproxy.http.HTTPFlow):
        if not self._in_scope(f.request.pretty_url):
            return
        self.hook_bus.publish("request", Flow.from_mitmproxy(f))

    def response(self, f: mitmproxy.http.HTTPFlow):
        if not self._in_scope(f.request.pretty_url):
            return
        flow = Flow.from_mitmproxy(f)
        self.hook_bus.publish("response", flow)
        self.hook_bus.publish("done", flow)
        self.hook_bus.publish("flow", flow)

    def error(self, f: mitmproxy.http.HTTPFlow):
        if not self._in_scope(f.request.pretty_url):
            return
        self.hook_bus.publish("error", Flow.from_mitmproxy(f))
