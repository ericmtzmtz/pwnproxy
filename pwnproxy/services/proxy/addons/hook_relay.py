import logging
import mitmproxy.http
from mitmproxy import flow

from pwnproxy.shared.hooks import HookBus
from pwnproxy.shared.models import Flow

logger = logging.getLogger(__name__)


class HookRelayAddon:
    """Mitmproxy addon that forwards events to the HookBus."""

    def __init__(self, hook_bus: HookBus, flow_filter=None, session_name_fn=None):
        self.hook_bus = hook_bus
        self._flow_filter = flow_filter
        self._session_name_fn = session_name_fn

    def _in_scope(self, url: str) -> bool:
        if self._flow_filter is None:
            return True
        return self._flow_filter.allow(url)

    def _tag(self, flow: Flow) -> Flow:
        if self._session_name_fn:
            try:
                sid = self._session_name_fn()
                if sid and not flow.session_id:
                    flow.session_id = sid
            except Exception:
                pass
        return flow

    def request(self, f: mitmproxy.http.HTTPFlow):
        if not self._in_scope(f.request.pretty_url):
            return
        flow = self._tag(Flow.from_mitmproxy(f))
        self.hook_bus.publish("request", flow)

    def response(self, f: mitmproxy.http.HTTPFlow):
        if not self._in_scope(f.request.pretty_url):
            return
        flow = self._tag(Flow.from_mitmproxy(f))
        self.hook_bus.publish("response", flow)
        self.hook_bus.publish("done", flow)
        self.hook_bus.publish("flow", flow)

    def error(self, f: mitmproxy.http.HTTPFlow):
        if not self._in_scope(f.request.pretty_url):
            return
        flow = self._tag(Flow.from_mitmproxy(f))
        self.hook_bus.publish("error", flow)
