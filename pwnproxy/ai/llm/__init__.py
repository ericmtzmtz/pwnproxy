"""Unified LLM client: local-first, provider chain with fallback."""
from pwnproxy.ai.llm.client import (
    CircuitBreaker,
    LLMClient,
    UnifiedLLMClient,
    extract_json,
)
from pwnproxy.ai.llm.config import LLMSettings, load_llm_config
from pwnproxy.ai.llm.errors import (
    LLMConfigError,
    LLMError,
    LLMSchemaError,
    LLMTimeout,
    LLMUnavailable,
)
from pwnproxy.ai.llm.models import LLMMessage, LLMRequest, LLMResponse
from pwnproxy.ai.llm.providers import create_client_from_config

__all__ = [
    "CircuitBreaker",
    "LLMClient",
    "LLMConfigError",
    "LLMError",
    "LLMMessage",
    "LLMRequest",
    "LLMResponse",
    "LLMSchemaError",
    "LLMSettings",
    "LLMTimeout",
    "LLMUnavailable",
    "UnifiedLLMClient",
    "create_client_from_config",
    "extract_json",
    "load_llm_config",
]

