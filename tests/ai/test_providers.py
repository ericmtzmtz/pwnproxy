"""Unit tests for each HTTP adapter using httpx.MockTransport."""
import json
import httpx
import pytest

from pwnproxy.ai.llm.errors import LLMRateLimited, LLMTimeout, LLMUnavailable
from pwnproxy.ai.llm.models import LLMMessage, LLMRequest
from pwnproxy.ai.llm.providers.anthropic import AnthropicProvider
from pwnproxy.ai.llm.providers.ollama import OllamaProvider
from pwnproxy.ai.llm.providers.openai import OpenAIProvider


def _req(json_mode: bool = False) -> LLMRequest:
    return LLMRequest(
        messages=[LLMMessage(role="system", content="be brief"), LLMMessage(role="user", content="hello")],
        json_mode=json_mode,
    )


class TestOllamaProvider:
    @pytest.mark.asyncio
    async def test_generate_ok(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            seen["payload"] = json.loads(request.content)
            return httpx.Response(200, json={"model": "llama3.2", "message": {"role": "assistant", "content": "hola"}, "prompt_eval_count": 5, "eval_count": 7})

        provider = OllamaProvider(timeout_s=5)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            resp = await provider.generate(_req(), http)
        assert resp.text == "hola"
        assert resp.provider == "ollama"
        assert resp.input_tokens == 5 and resp.output_tokens == 7
        assert seen["url"].endswith("/api/chat")
        assert seen["payload"]["messages"][1]["content"] == "hello"

    @pytest.mark.asyncio
    async def test_json_mode_sets_format(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["payload"] = json.loads(request.content)
            return httpx.Response(200, json={"message": {"content": "{}"}})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            await OllamaProvider().generate(_req(json_mode=True), http)
        assert seen["payload"]["format"] == "json"

    @pytest.mark.asyncio
    async def test_missing_content_is_unavailable(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"nope": True})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            with pytest.raises(LLMUnavailable):
                await OllamaProvider().generate(_req(), http)


class TestOpenAIProvider:
    @pytest.mark.asyncio
    async def test_generate_ok_with_auth_and_usage(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["auth"] = request.headers.get("Authorization")
            seen["payload"] = json.loads(request.content)
            return httpx.Response(200, json={"model": "gpt-4o-mini", "choices": [{"message": {"content": "hi"}}], "usage": {"prompt_tokens": 11, "completion_tokens": 13}})

        provider = OpenAIProvider(api_key="sk-test")
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            resp = await provider.generate(_req(), http)
        assert resp.text == "hi" and resp.input_tokens == 11 and resp.output_tokens == 13
        assert seen["auth"] == "Bearer sk-test"

    @pytest.mark.asyncio
    async def test_json_mode_response_format(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["payload"] = json.loads(request.content)
            return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            await OpenAIProvider(api_key="k").generate(_req(json_mode=True), http)
        assert seen["payload"]["response_format"] == {"type": "json_object"}

    @pytest.mark.asyncio
    async def test_500_maps_to_rate_limited(self):
        # 5xx is transient (retryable at the client) → LLMRateLimited, not a hard unavailable.
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(500))) as http:
            with pytest.raises(LLMRateLimited):
                await OpenAIProvider(api_key="k").generate(_req(), http)

    @pytest.mark.asyncio
    async def test_429_maps_to_rate_limited_with_retry_after(self):
        async def handler(req):
            return httpx.Response(429, headers={"retry-after": "3"})
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            with pytest.raises(LLMRateLimited) as ei:
                await OpenAIProvider(api_key="k").generate(_req(), http)
            assert ei.value.retry_after_s == 3.0

    @pytest.mark.asyncio
    async def test_400_maps_to_unavailable(self):
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(400))) as http:
            with pytest.raises(LLMUnavailable):
                await OpenAIProvider(api_key="k").generate(_req(), http)


class TestAnthropicProvider:
    @pytest.mark.asyncio
    async def test_generate_ok_system_extracted(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["headers"] = dict(request.headers)
            seen["payload"] = json.loads(request.content)
            return httpx.Response(200, json={"model": "claude-3-5-haiku-latest", "content": [{"type": "text", "text": "bonjour"}], "usage": {"input_tokens": 3, "output_tokens": 4}})

        provider = AnthropicProvider(api_key="ak-test")
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            resp = await provider.generate(_req(), http)
        assert resp.text == "bonjour" and resp.output_tokens == 4
        assert seen["headers"].get("x-api-key") == "ak-test"
        assert seen["payload"]["system"] == "be brief"
        assert all(m["role"] != "system" for m in seen["payload"]["messages"])

    @pytest.mark.asyncio
    async def test_timeout_maps_to_llmtimeout(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectTimeout("slow", request=request)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            with pytest.raises(LLMTimeout):
                await AnthropicProvider(api_key="k").generate(_req(), http)

    @pytest.mark.asyncio
    async def test_bad_json_body_maps_to_unavailable(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="<html>oops</html>")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            with pytest.raises(LLMUnavailable, match="JSON"):
                await OllamaProvider().generate(_req(), http)



