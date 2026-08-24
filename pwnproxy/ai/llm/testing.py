"""Test doubles for the LLM layer: FakeLLMClient for future consumers (triage, reports)."""
from typing import Optional, TypeVar

from pydantic import BaseModel

from pwnproxy.ai.llm.errors import LLMError
from pwnproxy.ai.llm.models import LLMRequest, LLMResponse
from pwnproxy.ai.llm.providers.base import Provider

T = TypeVar("T", bound=BaseModel)


class FakeLLMClient:
    """Scripted client. Queue holds str (ok), Exception (raise), or BaseModel (structured ok).

    Records every request in .calls and every structured call in .structured_calls.
    """

    def __init__(self, queue: Optional[list] = None):
        self.queue: list = list(queue or [])
        self.calls: list[LLMRequest] = []
        self.structured_calls: list[tuple[LLMRequest, type]] = []

    def push(self, item) -> "FakeLLMClient":
        self.queue.append(item)
        return self

    async def generate(self, request: LLMRequest) -> LLMResponse:
        self.calls.append(request)
        item = self._next()
        if isinstance(item, BaseException):
            raise item
        text = item if isinstance(item, str) else item.model_dump_json()
        return LLMResponse(text=text, provider="fake", model="fake-1")

    async def generate_structured(self, request: LLMRequest, schema: type[T]) -> tuple[T, LLMResponse]:
        self.structured_calls.append((request, schema))
        resp = await self.generate(request)
        parsed = schema.model_validate_json(resp.text)
        return parsed, resp

    def _next(self):
        if not self.queue:
            raise LLMError("FakeLLMClient queue is empty")
        return self.queue.pop(0)


class RecordingProvider(Provider):
    """Provider double that never touches the network; scripted outcomes per call."""

    name = "recording"
    default_model = "recording-1"

    @property
    def default_base_url(self) -> str:
        return "http://recording.invalid"

    def __init__(self, outcomes: Optional[list] = None, **kwargs):
        super().__init__(**kwargs)
        self.outcomes = list(outcomes or [])
        self.requests: list[LLMRequest] = []

    def _pop(self):
        return self.outcomes.pop(0) if self.outcomes else ""

    async def generate(self, request, http):
        from pwnproxy.ai.llm.models import LLMResponse

        self.requests.append(request)
        item = self._pop()
        if isinstance(item, BaseException):
            raise item
        return LLMResponse(
            text=str(item),
            provider=self.name,
            model=self.model,
            input_tokens=1,
            output_tokens=2,
            latency_ms=3,
        )
