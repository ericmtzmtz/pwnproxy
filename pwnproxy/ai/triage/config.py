"""[triage] section in ~/.pwnproxy/config.toml + PWNPROXY_TRIAGE_* env overrides."""
import os
import tomllib
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

DEFAULT_WEIGHTS: dict[str, float] = {
    "no_evidence": -0.45,
    "tentative_confidence": -0.20,
    "confident_confidence": 0.15,
    "detailed_evidence": 0.10,
    "payload_in_evidence": 0.15,
    "request_context": 0.05,
}


class TriageConfig(BaseModel):
    enabled: bool = True
    auto_true: float = 0.7
    auto_false: float = 0.3
    queue_maxsize: int = 500
    weights: dict[str, float] = Field(default_factory=lambda: dict(DEFAULT_WEIGHTS))


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

    return TriageConfig(
        enabled=_bool(env.get("PWNPROXY_TRIAGE_ENABLED") or data.get("enabled"), default=True),
        auto_true=float(env.get("PWNPROXY_TRIAGE_AUTO_TRUE") or data.get("auto_true") or 0.7),
        auto_false=float(env.get("PWNPROXY_TRIAGE_AUTO_FALSE") or data.get("auto_false") or 0.3),
        queue_maxsize=int(env.get("PWNPROXY_TRIAGE_QUEUE_MAXSIZE") or data.get("queue_maxsize") or 500),
        weights=weights,
    )


def _bool(raw, default: bool) -> bool:
    if raw is None:
        return default
    if isinstance(raw, bool):
        return raw
    return str(raw).strip().lower() in ("1", "true", "yes", "on")
