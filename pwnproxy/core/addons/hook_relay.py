import logging
import mitmproxy.http
from mitmproxy import flow

from pwnproxy.core.hooks import HookBus
from pwnproxy.core.models import Flow

logger = logging.getLogger(__name__)


class HookRelayAddon:
    """Mitmproxy addon that forwards events to the HookBus."""
    
    def __init__(self, hook_bus: HookBus):
        self.hook_bus = hook_bus

    def request(self, f: mitmproxy.http.HTTPFlow):
        self.hook_bus.publish("request", Flow.from_mitmproxy(f))

    def response(self, f: mitmproxy.http.HTTPFlow):
        flow = Flow.from_mitmproxy(f)
        self.hook_bus.publish("response", flow)
        self.hook_bus.publish("done", flow)

    def error(self, f: mitmproxy.http.HTTPFlow):
        self.hook_bus.publish("error", Flow.from_mitmproxy(f))
