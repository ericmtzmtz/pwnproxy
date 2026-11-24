"""Canonical event topic constants.

Events are notifications — the owner of the state remains the single source
of truth. See docs/ownership-matrix.md.
"""

from enum import Enum


class QoSClass(str, Enum):
    """Event priority classes for backpressure and queue policies.

    - CRITICAL: FindingCreated, JobStateChanged, scope updates — never dropped.
    - IMPORTANT: progress updates, triage — coalesce by key when congested.
    - BEST_EFFORT: flow/URL verbose — dropped first under pressure.
    """

    CRITICAL = "critical"
    IMPORTANT = "important"
    BEST_EFFORT = "best_effort"


# Scope
SCOPE_UPDATED = "scope.updated"

# Jobs (used by crawler, scanners, etc.)
JOB_STATE_CHANGED = "job.state_changed"

# Crawler
CRAWL_STARTED = "crawl.started"
CRAWL_PROGRESS = "crawl.progress"
CRAWL_COMPLETED = "crawl.completed"
CRAWL_FAILED = "crawl.failed"
CRAWLER_FLOW = "crawler.flow"
CRAWLER_URL = "crawler.url"

# Bruteforce
BRUTEFORCE_STARTED = "bruteforce.started"
BRUTEFORCE_PROGRESS = "bruteforce.progress"
BRUTEFORCE_COMPLETED = "bruteforce.completed"
BRUTEFORCE_FAILED = "bruteforce.failed"
BRUTEFORCE_URL = "bruteforce.url"

# Scanning
SCAN_STARTED = "scan.started"
SCAN_COMPLETED = "scan.completed"

# Auto-scan (proxy flow path, windowed)
AUTOSCAN_STARTED = "autoscan.started"
AUTOSCAN_COMPLETED = "autoscan.completed"

# Findings
FINDING_CREATED = "finding.created"
TRIAGE_UPDATED = "triage.updated"

#: A finding row that is already persisted in the session database. This is the
#: only finding channel the WebSocket relays (``/ws/findings``, ``/ws/events``
#: and the ``findings:`` rooms) read: the payload is the stored row as a ``dict``
#: (columns of the ``findings`` table plus ``session_id``), never the raw
#: ``Finding`` dataclass a plugin yields. The raw ``finding`` hook channel stays
#: for plugins that declare ``consumes=["finding"]``.
FINDING_STORED = "finding.stored"

#: A plugin's configuration changed through the API (settings, a collection item
#: or an action). The payload carries the **names** of the keys that changed and
#: never a value (see ``plugins/core/config_service.py``): it is the audit trail
#: of the change, the plugin keeps the only store.
PLUGIN_CONFIG_CHANGED = "plugin.config_changed"


# ── QoS classification ─────────────────────────────────────────────
# Every topic MUST have a QoS class. New topics added without one
# default to BEST_EFFORT (fail-safe: drop before blocking producer).

TOPIC_QOS: dict[str, QoSClass] = {
    # CRITICAL — must reach consumers; retry in-memory on congestion
    FINDING_CREATED:       QoSClass.CRITICAL,
    JOB_STATE_CHANGED:     QoSClass.CRITICAL,
    SCOPE_UPDATED:         QoSClass.CRITICAL,
    CRAWL_STARTED:         QoSClass.CRITICAL,
    CRAWL_FAILED:          QoSClass.CRITICAL,
    CRAWL_COMPLETED:       QoSClass.CRITICAL,
    BRUTEFORCE_STARTED:    QoSClass.CRITICAL,
    BRUTEFORCE_COMPLETED:  QoSClass.CRITICAL,
    BRUTEFORCE_FAILED:     QoSClass.CRITICAL,
    SCAN_STARTED:          QoSClass.CRITICAL,
    SCAN_COMPLETED:        QoSClass.CRITICAL,
    AUTOSCAN_STARTED:      QoSClass.IMPORTANT,
    AUTOSCAN_COMPLETED:    QoSClass.IMPORTANT,
    FINDING_STORED:        QoSClass.CRITICAL,

    # CRITICAL — an audit trail (who changed what), not telemetry: losing the
    # last change before a crash would lose the record of it.
    PLUGIN_CONFIG_CHANGED: QoSClass.CRITICAL,

    # IMPORTANT — coalesce by key (e.g. progress:{job_id}) on congestion
    CRAWL_PROGRESS:        QoSClass.IMPORTANT,
    BRUTEFORCE_PROGRESS:   QoSClass.IMPORTANT,
    TRIAGE_UPDATED:        QoSClass.IMPORTANT,

    # BEST_EFFORT — dropped first when queues fill up
    CRAWLER_FLOW:          QoSClass.BEST_EFFORT,
    CRAWLER_URL:           QoSClass.BEST_EFFORT,
    BRUTEFORCE_URL:        QoSClass.BEST_EFFORT,
}

# Internal HookBus channel names (plugin consumers register + publish by these
# literal strings, see plugins/core/loader.py `_publish_results` and the WS
# event relays). Most overlap the canonical topics above; the proxy raw-flow /
# finding channels are only reachable via these names, so map them explicitly
# instead of letting them fall to DEFAULT_QOS (BEST_EFFORT).
HOOKBUS_QOS: dict[str, QoSClass] = {
    **TOPIC_QOS,
    # Plugin produce/consume channels
    "finding":             QoSClass.CRITICAL,   # plugin finding results → storage/WS
    "error":               QoSClass.CRITICAL,   # error events must not be dropped
    # Proxy raw-flow channels (high volume, verbose)
    "flow":                QoSClass.BEST_EFFORT,
    "flow_stored":         QoSClass.IMPORTANT,  # persisted-flow notification (UI live)
    "done":                QoSClass.BEST_EFFORT,
    "request":             QoSClass.BEST_EFFORT,
    "response":            QoSClass.BEST_EFFORT,
}

DEFAULT_QOS = QoSClass.BEST_EFFORT
