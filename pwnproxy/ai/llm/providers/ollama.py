"""Ollama adapter: POST /api/chat on a local daemon. No API key required."""
from typing import ClassVar, Optional

import httpx

from pwnproxy.ai.llm.errors import LLMUnavailable
from pwnproxy.ai.llm.models import LLMRequest, LLMResponse
from pwnproxy.ai.llm.providers.base import Provider


class OllamaProvider(Provider):
    name: ClassVar[str] = "ollama"
    default_model: ClassVar[str] = "llama3.2"

    @property
    def default_base_url(self) -> str:
        return "http://127.0.0.1:11434"

    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None, base_url: Optional[str] = None, timeout_s: float = 30.0):
        super().__init__(model=model, api_key=None, base_url=base_url, timeout_s=timeout_s)

    async def generate(self, request: LLMRequest, http: httpx.AsyncClient) -> LLMResponse:
        payload: dict = {
            "model": request.model or self.model,
            "messages": [{"role": m.role, "content": m.content} for m in request.messages],
            "stream": False,
            "options": {"temperature": request.temperature},
        }
        if request.json_mode:
            payload["format"] = "json"
        data = await self._post(http, f"{self.base_url}/api/chat", {}, payload)
        message = data.get("message") or {}
        content = message.get("content")
        if content is None:
            raise LLMUnavailable(self.name, "ollama response missing message.content")
        return LLMResponse(
            text=content,
            provider=self.name,
            model=data.get("model", payload["model"]),
            input_tokens=int(data.get("prompt_eval_count") or 0),
            output_tokens=int(data.get("eval_count") or 0),
            latency_ms=getattr(self, "last_latency_ms", 0),
        )
