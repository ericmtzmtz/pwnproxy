"""Publication of a persisted finding as a live event.

The WebSocket relays (``/ws/findings``, ``/ws/events`` and the ``findings:``
rooms) only understand the **stored row**: a ``dict`` with the columns of the
``findings`` table plus ``session_id``. Whoever owns the write publishes here
right after a successful save — the plugin loader's storage consumer and
``POST /api/v1/findings`` — so both producers emit exactly the same shape and
the transport never has to guess what it received.

Publishing is best effort: a bus failure is logged, never raised, because the
finding is already persisted and losing the notification must not fail the
request or stop the loader's consumer loop.
"""

import logging
from typing import Any

from pwnproxy.shared.bus.topics import FINDING_STORED

logger = logging.getLogger(__name__)

#: HookBus channel that carries persisted finding rows to the WebSocket relays.
FINDING_STORED_CHANNEL = FINDING_STORED


def stored_event(row: dict, session_id: str | None = None) -> dict:
    """Return the ``finding.stored`` payload for a persisted finding row.

    Args:
        row: The stored row (``FindingORM`` columns as a ``dict``). It is copied,
            never mutated.
        session_id: Session name the finding belongs to; omitted when falsy so a
            caller without a session does not invent one.

    Returns:
        A new ``dict`` with every column of ``row`` and, when provided,
        ``session_id``.
    """
    event: dict[str, Any] = dict(row)
    if session_id:
        event["session_id"] = session_id
    return event


def publish_stored_finding(hook_bus: Any, row: dict, session_id: str | None = None) -> dict | None:
    """Publish a persisted finding row on :data:`FINDING_STORED_CHANNEL`.

    Call this **only after** a successful save: if the save failed there is no
    row to announce and nothing should reach the UI.

    Args:
        hook_bus: The ``HookBus`` (or ``None`` when the process has none).
        row: The stored row, as returned by ``FindingStorage.get``/``list``.
        session_id: Session name to tag the event with (rooms filter on it).

    Returns:
        The published payload, or ``None`` when no bus was given. A bus that
        raises while publishing is logged and still returns the payload: the
        finding is saved and the caller's work is done.
    """
    if hook_bus is None or not row:
        return None
    event = stored_event(row, session_id)
    try:
        hook_bus.publish(FINDING_STORED_CHANNEL, event)
    except Exception:  # a dead subscriber must not fail a persisted finding
        logger.warning("could not publish finding.stored for id=%s", event.get("id"), exc_info=True)
    return event
