"""Canonical cross-subsystem contracts (Pydantic v2).

These models are the single source of truth for data that crosses
subsystem boundaries (storage ↔ API ↔ events ↔ UI). Internal layers
may use their own types, but MUST serialize through these at boundaries.

See docs/ownership-matrix.md for the ownership rules.
"""

from pwnproxy.shared.contracts.job import Job, JobState, JobStats  # noqa: F401
