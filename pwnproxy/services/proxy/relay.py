"""Relay of proxy-worker events into the main process buses.

The proxy runs in its own process (:mod:`pwnproxy.services.proxy.proxy_worker`)
and reports what it captured over a TCP bridge. :func:`relay_worker_event` is
the single place where those events become ``HookBus`` / ``InProcessBus``
publications, so it is also the single place where the auto-scan rule lives: a
captured flow is only published on the channels the plugins consume (``flow``
and ``done``) when :meth:`FlowFilter.allow_active_scan` says yes.

Capture is *not* gated here. The worker persists to ``traffic.db`` and announces
``proxy.flow_stored``, which is relayed always: History and the live UI
(``/ws/events``) keep working with the scope off, exactly as before.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from pwnproxy.shared.models import Flow

logger = logging.getLogger(__name__)

#: Bridge topics that carry a captured flow. The suffix after the dot is the
#: HookBus channel the plugins subscribe to.
FLOW_TOPICS = ("proxy.flow", "proxy.done")

#: Bridge topic announcing that a flow reached ``traffic.db`` (never gated).
FLOW_STORED_TOPIC = "proxy.flow_stored"


def _tag_session(data: Any, session_name: str | None) -> None:
    """Tag a dict payload with the active session for the WS rooms (in place).

    Only the main process knows the active session; the worker does not. Keys
    already present win, so the writer stays the owner of the tag.
    """
    if isinstance(data, dict) and "session_id" not in data and session_name:
        data["session_id"] = session_name


def relay_worker_event(
    topic: str,
    data: Any,
    *,
    hook_bus,
    bus=None,
    flow_filter=None,
    session_name: str | None = None,
) -> None:
    """Publish one proxy-worker event on the main process buses.

    Args:
        topic: Bridge topic, e.g. ``proxy.flow``, ``proxy.done``,
            ``proxy.flow_stored`` or any other worker event (``proxy.scope``...).
        data: Payload sent by the worker (a ``Flow.to_dict()`` for the flow
            topics).
        hook_bus: ``HookBus`` of the main process (WebSocket relays, rooms).
        bus: Optional ``InProcessBus``; the plugin consumers subscribe there.
        flow_filter: ``FlowFilter`` holding the session scope. When present it
            decides whether the flow may reach the plugins; ``None`` means "no
            scope wired" (legacy/unit wiring) and lets the flow through.
        session_name: Active session name, tagged into the payload for the
            room-filtered WebSocket events.

    Note:
        An out-of-scope or scope-off flow is dropped **before** both publishes,
        so no plugin (core or installed) sees it and the auto-scan tracker does
        not count it. The flow itself is already in ``traffic.db`` and on
        ``flow_stored`` by then.
    """
    if topic in FLOW_TOPICS:
        flow = Flow.from_dict(data)
        if not flow.session_id and session_name:
            flow.session_id = session_name
        if flow_filter is not None and not flow_filter.allow_active_scan(flow.url):
            logger.debug(
                "auto-scan blocked for %s (%s)",
                flow.url,
                flow_filter.active_scan_blocked_reason(),
            )
            return
        channel = topic.split(".", 1)[1]
        hook_bus.publish(channel, flow)
        if bus is not None:
            asyncio.create_task(bus.publish(channel, flow))
        return

    _tag_session(data, session_name)
    if topic == FLOW_STORED_TOPIC:
        hook_bus.publish("flow_stored", data)
        return

    channel = topic.removeprefix("proxy.") if topic.startswith("proxy.") else topic
    hook_bus.publish(channel, data)
    if bus is not None:
        asyncio.create_task(bus.publish(channel, data))
