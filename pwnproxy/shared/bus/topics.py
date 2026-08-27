"""Canonical event topic constants.

Events are notifications — the owner of the state remains the single source
of truth. See docs/ownership-matrix.md.
"""

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
BRUTEFORCE_URL = "bruteforce.url"

# Scanning
SCAN_STARTED = "scan.started"
SCAN_COMPLETED = "scan.completed"

# Findings
FINDING_CREATED = "finding.created"
TRIAGE_UPDATED = "triage.updated"
