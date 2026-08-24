"""Provider registry + factory with fallback chain resolution."""
import httpx

from pwnproxy.ai.llm.config import LLMSettings, load_llm_config
from pwnproxy.ai.llm.providers.anthropic import AnthropicProvider
from pwnproxy.ai.llm.providers.base import Provider
from pwnproxy.ai.llm.providers.ollama import OllamaProvider
from pwnproxy.ai.llm.providers.openai import OpenAIProvider
from pwnproxy.ai.llm.usage import UsageLedger

PROVIDER_CLASSES: dict[str, type[Provider]] = {
    OllamaProvider.name: OllamaProvider,
    OpenAIProvider.name: OpenAIProvider,
    AnthropicProvider.name: AnthropicProvider,
}

__all__ = ["Provider", "PROVIDER_CLASSES", "build_providers", "create_client_from_config"]


def build_providers(settings: LLMSettings) -> dict[str, Provider]:
    return {
        name: cls(
            model=getattr(settings, name).model,
            api_key=getattr(settings, name).api_key,
            base_url=getattr(settings, name).base_url,
            timeout_s=settings.timeout_s,
        )
        for name, cls in PROVIDER_CLASSES.items()
    }


def resolve_chain(settings: LLMSettings) -> list[str]:
    """Explicit fallback_chain wins; else [provider] + cloud-with-keys; else local-first auto."""
    available: list[str] = ["ollama"]
    if settings.openai.api_key:
        available.append("openai")
    if settings.anthropic.api_key:
        available.append("anthropic")

    if settings.fallback_chain:
        chain = [p for p in settings.fallback_chain if p in PROVIDER_CLASSES]
        return chain or available[:1]
    if settings.provider:
        rest = [p for p in available if p != settings.provider]
        return [settings.provider] + rest if settings.provider in available else ([settings.provider] if settings.provider in PROVIDER_CLASSES else [])
    return available


def create_client_from_config(
    settings: LLMSettings | None = None,
    ledger: UsageLedger | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
):
    from pwnproxy.ai.llm.client import UnifiedLLMClient

    settings = settings or load_llm_config()
    settings.validate_providers()
    providers = build_providers(settings)
    chain = resolve_chain(settings)
    return UnifiedLLMClient(
        providers=providers,
        chain=chain,
        ledger=ledger,
        circuit_threshold=settings.circuit_threshold,
        cooldown_s=settings.cooldown_s,
        transport=transport,
    )

