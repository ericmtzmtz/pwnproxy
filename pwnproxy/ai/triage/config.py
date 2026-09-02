"""[triage] section in ~/.pwnproxy/config.toml + PWNPROXY_TRIAGE_* env overrides."""
import os
import tomllib
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

DEFAULT_WEIGHTS: dict[str, float] = {
    "no_evidence": -0.45,
    "tentative_confidence": -0.20,
    "inferred_confidence": 0.10,
    "confirmed_confidence": 0.20,
    "confident_confidence": 0.15,
    "detailed_evidence": 0.10,
    "payload_in_evidence": 0.15,
    "request_context": 0.05,
}

VALID_MODES = ("off", "heuristic", "enrich", "legacy_gray")


class TriageConfig(BaseModel):
    enabled: bool = True
    # How the LLM judge is used:
    #   "off"         — never call the LLM (heuristic only).
    #   "heuristic"   — (default) heuristic only; tentative findings never reach
    #                   the judge; confirmed/inferred in the gray zone stay
    #                   uncertain without LLM.
    #   "enrich"      — LLM as optional enrichment over already-strong findings
    #                   (confirmed/inferred), never to arbitrate the gray zone.
    #   "legacy_gray" — old behavior: gray-zone findings go to the judge,
    #                   bounded by max_llm_per_scan (opt-in).
    mode: str = "heuristic"
    auto_true: float = 0.7
    auto_false: float = 0.3
    queue_maxsize: int = 500
    weights: dict[str, float] = Field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    # Hard cap on LLM judge calls per scan (per scan_id; findings without a
    # scan_id share the "default" bucket). Guards cost after the SSRF FP flood.
    max_llm_per_scan: int = 20
    # Confidence levels that never reach the LLM judge (hard gate).
    skip_llm_if_confidence: list[str] = Field(default_factory=lambda: ["tentative"])
    # In "enrich" mode, a judge verdict of false_positive over a finding that
    # the scanner already marked confirmed/inferred is only applied when the
    # judge's own confidence meets this threshold. Below it the finding stays
    # as-is (or uncertain) — enrichment must not casually distrust the engine.
    enrich_fp_threshold: float = 0.85


def load_triage_config(config_dir: Optional[Path] = None) -> TriageConfig:
    config_dir = config_dir or (Path.home() / ".pwnproxy")
    config_path = config_dir / "config.toml"
    data: dict = {}
    if config_path.exists():
        try:
            data = tomllib.loads(config_path.read_text(encoding="utf-8")).get("triage", {})
        except Exception:
            data = {}

    env = os.environ
    weights = dict(DEFAULT_WEIGHTS)
    for key in list(weights):
        raw = data.get("weights", {}).get(key) if isinstance(data.get("weights"), dict) else None
        if raw is not None:
            try:
                weights[key] = float(raw)
            except (TypeError, ValueError):
                pass

    mode = str(env.get("PWNPROXY_TRIAGE_MODE") or data.get("mode") or "heuristic").lower()
    if mode not in VALID_MODES:
        mode = "heuristic"

    skip = data.get("skip_llm_if_confidence")
    if not isinstance(skip, list) or not skip:
        skip = ["tentative"]

    return TriageConfig(
        enabled=_bool(env.get("PWNPROXY_TRIAGE_ENABLED") or data.get("enabled"), default=True),
        mode=mode,
        auto_true=float(env.get("PWNPROXY_TRIAGE_AUTO_TRUE") or data.get("auto_true") or 0.7),
        auto_false=float(env.get("PWNPROXY_TRIAGE_AUTO_FALSE") or data.get("auto_false") or 0.3),
        queue_maxsize=int(env.get("PWNPROXY_TRIAGE_QUEUE_MAXSIZE") or data.get("queue_maxsize") or 500),
        max_llm_per_scan=int(env.get("PWNPROXY_TRIAGE_MAX_LLM_PER_SCAN") or data.get("max_llm_per_scan") or 20),
        skip_llm_if_confidence=[str(c).lower() for c in skip],
        enrich_fp_threshold=float(
            env.get("PWNPROXY_TRIAGE_ENRICH_FP_THRESHOLD") or data.get("enrich_fp_threshold") or 0.85
        ),
        weights=weights,
    )


def _bool(raw, default: bool) -> bool:
    if raw is None:
        return default
    if isinstance(raw, bool):
        return raw
    return str(raw).strip().lower() in ("1", "true", "yes", "on")
