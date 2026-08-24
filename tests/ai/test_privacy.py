"""Privacy: without cloud keys configured, zero requests leave the host."""
import json

import httpx
import pytest

from pwnproxy.ai.llm.config import LLMSettings, ProviderSettings
from pwnproxy.ai.llm.providers import create_client_from_config
from pwnproxy.ai.llm.errors import LLMTimeout
from pwnproxy.ai.llm.models import LLMMessage, LLMRequest


def _local_only_settings() -> LLMSettings:
    return LLMSettings(
        provider=None,
        fallback_chain=[],
        ollama=ProviderSettings(model="llama3.2", base_url="http://127.0.0.1:11434"),
        openai=ProviderSettings(model="gpt-4o-mini", api_key=None),
        anthropic=ProviderSettings(model="claude-3-5-haiku-latest", api_key=None),
    )


def _req() -> LLMRequest:
    return LLMRequest(messages=[LLMMessage(role="user", content="analyze this")])


class TestPrivacyLocalFirst:
    def test_chain_is_local_only_without_keys(self):
        client = create_client_from_config(settings=_local_only_settings())
        assert client.chain == ["ollama"]

    @pytest.mark.asyncio
    async def test_no_outbound_cloud_requests_even_when_local_fails(self):
        hosts = []

        def handler(request: httpx.Request) -> httpx.Response:
            hosts.append(request.url.host)
            raise httpx.ConnectTimeout("ollama down", request=request)

        client = create_client_from_config(settings=_local_only_settings(), transport=httpx.MockTransport(handler))
        with pytest.raises(LLMTimeout):
            await client.generate(_req())
        assert hosts, "expected the local provider to be attempted"
        assert all(h in ("127.0.0.1", "localhost") for h in hosts), f"non-local host contacted: {hosts}"

    @pytest.mark.asyncio
    async def test_happy_path_stays_local(self):
        hosts = []

        def handler(request: httpx.Request) -> httpx.Response:
            hosts.append(request.url.host)
            return httpx.Response(200, json={"message": {"content": "ok"}, "prompt_eval_count": 1, "eval_count": 1})

        client = create_client_from_config(settings=_local_only_settings(), transport=httpx.MockTransport(handler))
        resp = await client.generate(_req())
        assert resp.provider == "ollama"
        assert all(h in ("127.0.0.1", "localhost") for h in hosts)

    def test_explicit_provider_requires_known_name(self):
        from pwnproxy.ai.llm.errors import LLMConfigError

        settings = _local_only_settings()
        settings.provider = "skynet"
        with pytest.raises(LLMConfigError):
            create_client_from_config(settings=settings)

