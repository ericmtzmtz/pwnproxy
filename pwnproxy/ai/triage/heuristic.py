"""Transparent weighted heuristic scorer for findings (v0)."""
import logging
from dataclasses import dataclass, field
from typing import Optional

from pwnproxy.ai.triage.config import TriageConfig

logger = logging.getLogger(__name__)

BASE_SCORE = 0.5
DETAILED_EVIDENCE_LEN = 120


@dataclass
class HeuristicResult:
    score: float
    reasons: list[str] = field(default_factory=list)
    features: dict = field(default_factory=dict)


def score_finding(row: dict, config: Optional[TriageConfig] = None) -> HeuristicResult:
    """Score a finding row dict. Pure function: no DB, no LLM, deterministic."""
    cfg = config or TriageConfig()
    w = cfg.weights

    evidence = str(row.get("evidence") or "").strip()
    payload = str(row.get("payload") or "").strip()
    confidence = str(row.get("confidence") or "").lower()
    request_data = row.get("request_data")

    score = BASE_SCORE
    reasons: list[str] = []
    features: dict = {"evidence_len": len(evidence), "has_request_data": bool(request_data)}

    if evidence:
        if len(evidence) >= DETAILED_EVIDENCE_LEN:
            score += w.get("detailed_evidence", 0.0)
            reasons.append("strong_evidence")
        if payload and payload in evidence:
            score += w.get("payload_in_evidence", 0.0)
            reasons.append("strong_evidence")
    else:
        score += w.get("no_evidence", 0.0)
        reasons.append("no_evidence")

    if confidence == "tentative":
        score += w.get("tentative_confidence", 0.0)
        reasons.append("scanner_noise")
    elif confidence == "confirmed":
        # Scanner already proved the payload took effect (SQL error surfaced,
        # XSS breakout executed). Strong bonus + a floor so it can never fall
        # into uncertain/auto_false regardless of generic evidence weights.
        score += w.get("confirmed_confidence", 0.0)
        reasons.append("confirmed_scanner")
    elif confidence == "inferred":
        score += w.get("inferred_confidence", 0.0)
        reasons.append("inferred_scanner")
    elif confidence in ("confident", "certain", "firm"):
        score += w.get("confident_confidence", 0.0)
        reasons.append("confident_scanner")

    if request_data:
        score += w.get("request_context", 0.0)
        reasons.append("request_context")

    final = round(min(1.0, max(0.0, score)), 3)
    if confidence == "confirmed" and final < cfg.auto_true:
        final = cfg.auto_true
        reasons.append("confirmed_floor")
    # Dedup preserving order (payload_in_evidence and detailed_evidence share the tag).
    reasons = list(dict.fromkeys(reasons))
    logger.debug("triage heuristic finding=%s score=%.3f reasons=%s", row.get("id"), final, reasons)
    return HeuristicResult(score=final, reasons=reasons, features=features)
