"""Vulnerability finding model.

Lives in ``shared`` because the detection stages (also ``shared``) produce
findings; ``plugins.core.base`` re-exports it for backwards compatibility.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class Finding:
    """Represents a vulnerability finding detected by a scanner plugin.

    Attributes:
        scanner: The name of the scanner plugin that detected the finding (e.g., "sqli", "xss").
        url: The target URL where the finding was detected.
        method: The HTTP method of the request (e.g., "GET", "POST").
        param_name: The name of the parameter that was tested.
        param_location: The location of the parameter ("query", "body", "cookie", "header").
        technique: The detection technique used (e.g., "error-based", "boolean-blind").
        severity: The severity of the finding ("low", "medium", "high", "critical").
        confidence: The confidence level of the finding. Three levels:
            - "tentative": a weak signal (e.g. unescaped reflection without a
              working exploit). Never by itself exploitable; reported only as
              an aid for review.
            - "inferred": a deterministic differential between two responses
              (e.g. boolean-blind TRUE vs FALSE across 4 stable rounds) but no
              direct code execution observed. Strong but not definitive.
            - "confirmed": the payload demonstrably took effect (e.g. SQL error
              surfaced, XSS breakout executed). Definitive; should be treated
              as exploitable.
        payload: The payload that triggered the finding.
        evidence: Human-readable string describing what was observed (e.g., "Response length diff: ...").
        timestamp: UTC datetime when the finding was detected.
        extra: Optional dictionary for scanner-specific metadata.
    """
    scanner: str
    url: str
    method: str
    param_name: str
    param_location: str
    technique: str
    severity: str
    confidence: str
    payload: str
    evidence: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    extra: dict = field(default_factory=dict)
    request_data: dict | None = None
