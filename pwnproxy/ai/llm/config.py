"""LLM settings: [ai] section in ~/.pwnproxy/config.toml + PWNPROXY_AI_* env overrides."""
import os
import tomllib
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from pwnproxy.ai.llm.errors import LLMConfigError

KNOWN_PROVIDERS = ("ollama", "openai", "anthropic")


class ProviderSettings(BaseModel):
    model: Optional[str] = None
    api_key: Optional[str] = None
    base_url: Optional[str] = None


class LLMSettings(BaseModel):
    provider: Optional[str] = None
    fallback_chain: list[str] = Field(default_factory=list)
    timeout_s: float = 30.0
    circuit_threshold: int = 3
    cooldown_s: float = 60.0
    ollama: ProviderSettings = Field(default_factory=lambda: ProviderSettings(model="llama3.2", base_url="http://127.0.0.1:11434"))
    openai: ProviderSettings = Field(default_factory=lambda: ProviderSettings(model="gpt-4o-mini"))
    anthropic: ProviderSettings = Field(default_factory=lambda: ProviderSettings(model="claude-3-5-haiku-latest"))

    def validate_providers(self) -> None:
        for name in ([self.provider] if self.provider else []) + self.fallback_chain:
            if name not in KNOWN_PROVIDERS:
                raise LLMConfigError(f"unknown LLM provider '{name}' (known: {', '.join(KNOWN_PROVIDERS)})")


def load_llm_config(config_dir: Optional[Path] = None) -> LLMSettings:
    config_dir = config_dir or (Path.home() / ".pwnproxy")
    config_path = config_dir / "config.toml"
    data: dict = {}
    if config_path.exists():
        try:
            data = tomllib.loads(config_path.read_text(encoding="utf-8")).get("ai", {})
        except Exception:
            data = {}

    env = os.environ
    def _key(name: str) -> Optional[str]:
        return env.get(name) or None

    settings = LLMSettings(
        provider=env.get("PWNPROXY_AI_PROVIDER") or data.get("provider"),
        fallback_chain=_chain(env.get("PWNPROXY_AI_FALLBACK_CHAIN") or data.get("fallback_chain")),
        timeout_s=float(env.get("PWNPROXY_AI_TIMEOUT_S") or data.get("timeout_s") or 30.0),
        circuit_threshold=int(env.get("PWNPROXY_AI_CIRCUIT_THRESHOLD") or data.get("circuit_threshold") or 3),
        cooldown_s=float(env.get("PWNPROXY_AI_COOLDOWN_S") or data.get("cooldown_s") or 60.0),
        ollama=ProviderSettings(
            model=(env.get("PWNPROXY_AI_OLLAMA_MODEL") or _section(data, "ollama").get("model") or "llama3.2"),
            base_url=(env.get("PWNPROXY_AI_OLLAMA_BASE_URL") or _section(data, "ollama").get("base_url") or "http://127.0.0.1:11434"),
            api_key=None,
        ),
        openai=ProviderSettings(
            model=(_section(data, "openai").get("model") or "gpt-4o-mini"),
            api_key=(env.get("PWNPROXY_AI_OPENAI_API_KEY") or env.get("OPENAI_API_KEY") or _section(data, "openai").get("api_key")),
            base_url=(_section(data, "openai").get("base_url")),
        ),
        anthropic=ProviderSettings(
            model=(_section(data, "anthropic").get("model") or "claude-3-5-haiku-latest"),
            api_key=(env.get("PWNPROXY_AI_ANTHROPIC_API_KEY") or env.get("ANTHROPIC_API_KEY") or _section(data, "anthropic").get("api_key")),
            base_url=(_section(data, "anthropic").get("base_url")),
        ),
    )
    settings.validate_providers()
    return settings


def _section(data: dict, name: str) -> dict:
    section = data.get(name)
    return section if isinstance(section, dict) else {}


def _chain(raw) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    return [x.strip() for x in str(raw).split(",") if x.strip()]
