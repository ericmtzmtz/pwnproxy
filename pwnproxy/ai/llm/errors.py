"""Typed errors for the LLM layer."""


class LLMError(Exception):
    """Base class for all LLM layer errors."""


class LLMTimeout(LLMError):
    """A provider exceeded the configured timeout."""

    def __init__(self, provider: str, message: str = ""):
        self.provider = provider
        super().__init__(message or f"provider '{provider}' timed out")


class LLMUnavailable(LLMError):
    """A provider failed (connection, 5xx, bad payload) or none is configured."""

    def __init__(self, provider: str, message: str = ""):
        self.provider = provider
        super().__init__(message or f"provider '{provider}' unavailable")


class LLMSchemaError(LLMError):
    """Structured output could not be validated against the requested schema."""

    def __init__(self, message: str, raw_text: str = ""):
        self.raw_text = raw_text
        super().__init__(message)


class LLMConfigError(LLMError):
    """Invalid or missing configuration (unknown provider, bad settings)."""
