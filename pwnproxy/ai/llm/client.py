"""UnifiedLLMClient: provider chain with fallback, circuit breaker, structured output."""
import json
import logging
import re
import time
from typing import Optional, Protocol, TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from pwnproxy.ai.llm.errors import LLMSchemaError, LLMTimeout, LLMUnavailable
from pwnproxy.ai.llm.models import LLMMessage, LLMRequest, LLMResponse
from pwnproxy.ai.llm.usage import UsageLedger

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

_JSON_INSTRUCTION = (
    "Return ONLY a single valid JSON object that conforms to the requested schema. "
    "No prose, no markdown fences."
)


class LLMClient(Protocol):
    async def generate(self, request: LLMRequest) -> LLMResponse: ...
    async def generate_structured(self, request: LLMRequest, schema: type[T]) -> tuple[T, LLMResponse]: ...


class CircuitBreaker:
    """Per-provider breaker: opens after `threshold` consecutive failures for `cooldown_s`."""

    def __init__(self, threshold: int = 3, cooldown_s: float = 60.0):
        self.threshold = threshold
        self.cooldown_s = cooldown_s
        self._failures: dict[str, int] = {}
        self._opened_at: dict[str, float] = {}

    def is_open(self, provider: str) -> bool:
        opened_at = self._opened_at.get(provider)
        if opened_at is None:
            return False
        if (time.monotonic() - opened_at) >= self.cooldown_s:
            return False
        return True

    def record_success(self, provider: str) -> None:
        self._failures[provider] = 0
        self._opened_at.pop(provider, None)

    def record_failure(self, provider: str) -> None:
        self._failures[provider] = self._failures.get(provider, 0) + 1
        if self._failures[provider] >= self.threshold:
            self._opened_at[provider] = time.monotonic()


def extract_json(text: str) -> str:
    """Strip markdown fences / surrounding prose and return the JSON payload string."""
    cleaned = text.strip()
    fence = re.match(r"^```(?:json)?\s*(.*?)\s*```$", cleaned, re.DOTALL)
    if fence:
        cleaned = fence.group(1).strip()
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start != -1 and end > start:
        return cleaned[start : end + 1]
    return cleaned


class UnifiedLLMClient:
    """The only entry point consumers should use. Local-first by default."""

    def __init__(
        self,
        providers: dict,
        chain: list[str],
        ledger: Optional[UsageLedger] = None,
        circuit_threshold: int = 3,
        cooldown_s: float = 60.0,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ):
        self._providers = providers
        self._chain = chain
        self._ledger = ledger
        self.circuit = CircuitBreaker(circuit_threshold, cooldown_s)
        self._http = httpx.AsyncClient(transport=transport) if transport else httpx.AsyncClient()

    @property
    def chain(self) -> list[str]:
        return list(self._chain)

    def _summary(self, request: LLMRequest) -> str:
        last_user = next((m.content for m in reversed(request.messages) if m.role == "user"), "")
        return last_user

    async def generate(self, request: LLMRequest) -> LLMResponse:
        last_error: Exception | None = None
        for name in self._chain:
            provider = self._providers.get(name)
            if provider is None or self.circuit.is_open(name):
                continue
            try:
                resp = await provider.generate(request, self._http)
                self.circuit.record_success(name)
                if self._ledger is not None:
                    await self._ledger.record_ok(resp, self._summary(request))
                return resp
            except (LLMTimeout, LLMUnavailable) as e:
                self.circuit.record_failure(name)
                last_error = e
                logger.warning("LLM provider %s failed: %s (falling through chain)", name, e)
                if self._ledger is not None:
                    status = "timeout" if isinstance(e, LLMTimeout) else "error"
                    await self._ledger.record_error(name, status, str(e), self._summary(request))
        if last_error is not None:
            raise last_error
        raise LLMUnavailable("-", "no LLM provider configured (set an api_key or install/run Ollama)")

    async def generate_structured(self, request: LLMRequest, schema: type[T]) -> tuple[T, "LLMResponse"]:
        first = request.model_copy(update={"json_mode": True})
        messages = list(first.messages)
        if not any(m.role == "system" and _JSON_INSTRUCTION in m.content for m in messages):
            messages.append(LLMMessage(role="system", content=_JSON_INSTRUCTION))
        first = first.model_copy(update={"messages": messages})

        resp = await self.generate(first)
        parsed = self._validate(resp.text, schema)
        if parsed is not None:
            return parsed, resp

        feedback = LLMSchemaError("invalid JSON/schema", raw_text=resp.text)
        retry_request = first.model_copy(
            update={
                "messages": [
                    *first.messages,
                    LLMMessage(role="assistant", content=resp.text),
                    LLMMessage(
                        role="user",
                        content=(
                            f"Your previous response was invalid: {feedback}\n"
                            "Respond again with ONLY the corrected JSON object."
                        ),
                    ),
                ]
            }
        )
        resp2 = await self.generate(retry_request)
        parsed2 = self._validate(resp2.text, schema)
        if parsed2 is not None:
            return parsed2, resp2
        raise LLMSchemaError(
            f"structured generation failed schema validation after retry: {parsed2 is None and parsed is None}",
            raw_text=resp2.text,
        )

    def _validate(self, text: str, schema: type[T]) -> Optional[T]:
        try:
            data = json.loads(extract_json(text))
        except json.JSONDecodeError:
            return None
        try:
            return schema.model_validate(data)
        except ValidationError:
            return None

    async def aclose(self) -> None:
        await self._http.aclose()
