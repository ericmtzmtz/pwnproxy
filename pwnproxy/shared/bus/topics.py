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
