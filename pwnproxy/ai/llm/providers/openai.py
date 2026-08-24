"""OpenAI adapter: chat completions with native JSON mode."""
from typing import ClassVar, Optional

import httpx

from pwnproxy.ai.llm.models import LLMRequest, LLMResponse
from pwnproxy.ai.llm.providers.base import Provider


class OpenAIProvider(Provider):
    name: ClassVar[str] = "openai"
    default_model: ClassVar[str] = "gpt-4o-mini"

    @property
    def default_base_url(self) -> str:
        return "https://api.openai.com/v1"

    async def generate(self, request: LLMRequest, http: httpx.AsyncClient) -> LLMResponse:
        payload: dict = {
            "model": request.model or self.model,
            "messages": [{"role": m.role, "content": m.content} for m in request.messages],
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
        }
        if request.json_mode:
            payload["response_format"] = {"type": "json_object"}
        data = await self._post(
            http,
            f"{self.base_url}/chat/completions",
            {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {},
            payload,
        )
        choice = (data.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        usage = data.get("usage") or {}
        return LLMResponse(
            text=message.get("text") or message.get("content") or "",
            provider=self.name,
            model=data.get("model", payload["model"]),
            input_tokens=int(usage.get("prompt_tokens") or 0),
            output_tokens=int(usage.get("completion_tokens") or 0),
            latency_ms=getattr(self, "last_latency_ms", 0),
        )
