"""``/ws/events`` relays ``plugin.config_changed`` so an open panel refreshes itself.

The event is the audit trail of the change: plugin, kind, target, item id, the
**names** of the keys that changed, the scope of the token and a timestamp — and
never a value. A client that keeps a settings tab open (the Web UI) listens to
this instead of polling, and the MCP/CLI path publishes to the same channel.

The read happens in a thread with ``join(timeout)``: ``receive_json`` blocks
forever, and a hanging test is not a red test (see ``docs/sesiones/plataforma.md``).
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime

from pwnproxy.shared.bus.topics import PLUGIN_CONFIG_CHANGED

from ._plugin_config_fakes import CANARY, NAME


def _receive_json(ws, timeout: float = 10.0) -> dict:
    """Receive one JSON message, failing (not hanging) when none arrives."""
    box: dict = {}

    def _read() -> None:
        try:
            box["message"] = ws.receive_json()
        except Exception as exc:  # a closed socket, a bad payload, ...
            box["error"] = exc

    reader = threading.Thread(target=_read, daemon=True)
    reader.start()
    reader.join(timeout)
    assert not reader.is_alive(), f"no WebSocket event within {timeout}s"
    assert "error" not in box, f"WebSocket read failed: {box.get('error')!r}"
    return box["message"]


def _wait_for_subscriber(bus, timeout: float = 5.0) -> None:
    """Wait until the socket handler registered its queue.

    ``websocket_connect`` returns as soon as the handshake is accepted, which is
    *before* the handler subscribes to the bus: publishing in between would be
    buffered by the bus and the test would race itself.
    """
    deadline = time.monotonic() + timeout
    while bus.get_subscriber_count(PLUGIN_CONFIG_CHANGED) == 0:
        assert time.monotonic() < deadline, "the events socket never subscribed"
        time.sleep(0.01)


class TestPluginConfigEvent:
    # @escenario plugin-config/auditoria/el-evento-llega-al-websocket
    def test_a_write_from_another_channel_reaches_the_events_socket(self, plugin_config):
        scene = plugin_config()

        with scene.client.websocket_connect("/ws/events") as ws:
            _wait_for_subscriber(scene.bus)
            # The HTTP API is "another channel": same process, other endpoint.
            response = scene.client.patch(
                f"/api/v1/plugins/{NAME}/settings", json={"values": {"signing_key": CANARY}}
            )
            event = _receive_json(ws)

        timestamp = event.pop("timestamp")
        assert (
            response.status_code,
            event,
            datetime.fromisoformat(timestamp) is not None,
            CANARY in json.dumps(event),
        ) == (
            200,
            {
                "type": PLUGIN_CONFIG_CHANGED,
                "plugin": NAME,
                "kind": "settings",
                "target": "settings",
                "item_id": None,
                "changed": ["signing_key"],
                "scope": "full",
            },
            True,
            False,
        )

    def test_the_event_of_an_action_names_the_action(self, plugin_config):
        scene = plugin_config()

        with scene.client.websocket_connect("/ws/events") as ws:
            _wait_for_subscriber(scene.bus)
            response = scene.client.post(
                f"/api/v1/plugins/{NAME}/actions/probe", json={"parameters": {}}
            )
            event = _receive_json(ws)

        event.pop("timestamp")
        assert (response.status_code, event) == (
            200,
            {
                "type": PLUGIN_CONFIG_CHANGED,
                "plugin": NAME,
                "kind": "action",
                "target": "probe",
                "item_id": None,
                "changed": [],
                "scope": "full",
            },
        )
