"""Unified LLM client: local-first, provider chain with fallback."""
from pwnproxy.ai.llm.client import LLMClient, UnifiedLLMClient, CircuitBreaker, extract_json
from pwnproxy.ai.llm.config import LLMSettings, load_llm_config
from pwnproxy.ai.llm.providers import create_client_from_config
from pwnproxy.ai.llm.errors import (
    LLMConfigError,
    LLMError,
    LLMSchemaError,
    LLMTimeout,
    LLMUnavailable,
)
from pwnproxy.ai.llm.models import LLMMessage, LLMRequest, LLMResponse

__all__ = [
    "LLMClient",
    "UnifiedLLMClient",
    "CircuitBreaker",
    "extract_json",
    "LLMSettings",
    "load_llm_config",
    "create_client_from_config",
    "LLMMessage",
    "LLMRequest",
    "LLMResponse",
    "LLMConfigError",
    "LLMError",
    "LLMSchemaError",
    "LLMTimeout",
    "LLMUnavailable",
]

