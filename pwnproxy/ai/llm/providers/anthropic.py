"""Anthropic adapter: messages API (system goes in its own field)."""
from typing import ClassVar, Optional

import httpx

from pwnproxy.ai.llm.models import LLMRequest, LLMResponse
from pwnproxy.ai.llm.providers.base import Provider


class AnthropicProvider(Provider):
    name: ClassVar[str] = "anthropic"
    default_model: ClassVar[str] = "claude-3-5-haiku-latest"

    @property
    def default_base_url(self) -> str:
        return "https://api.anthropic.com"

    async def generate(self, request: LLMRequest, http: httpx.AsyncClient) -> LLMResponse:
        system_parts = [m.content for m in request.messages if m.role == "system"]
        messages = [
            {"role": m.role, "content": m.content}
            for m in request.messages
            if m.role in ("user", "assistant")
        ]
        payload: dict = {
            "model": request.model or self.model,
            "messages": messages,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
        }
        if system_parts:
            payload["system"] = "\n\n".join(system_parts)
        data = await self._post(
            http,
            f"{self.base_url}/v1/messages",
            {
                "x-api-key": self.api_key or "",
                "anthropic-version": "2023-06-01",
            },
            payload,
        )
        text = "".join(block.get("text", "") for block in data.get("content", []) if isinstance(block, dict))
        usage = data.get("usage") or {}
        return LLMResponse(
            text=text,
            provider=self.name,
            model=data.get("model", payload["model"]),
            input_tokens=int(usage.get("input_tokens") or 0),
            output_tokens=int(usage.get("output_tokens") or 0),
            latency_ms=getattr(self, "last_latency_ms", 0),
        )
