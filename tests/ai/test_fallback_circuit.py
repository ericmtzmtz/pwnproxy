"""Fallback chain + circuit breaker behavior."""
import asyncio

import pytest

from pwnproxy.ai.llm.client import CircuitBreaker, UnifiedLLMClient
from pwnproxy.ai.llm.errors import LLMTimeout, LLMUnavailable
from pwnproxy.ai.llm.models import LLMMessage, LLMRequest
from pwnproxy.ai.llm.testing import RecordingProvider


def _req() -> LLMRequest:
    return LLMRequest(messages=[LLMMessage(role="user", content="ping")])


def _client(outcomes_p1: list, outcomes_p2: list | None = None, threshold: int = 3, cooldown_s: float = 60.0) -> UnifiedLLMClient:
    p1 = RecordingProvider(outcomes=outcomes_p1)
    p1.name = "p1"
    providers = {"p1": p1}
    chain = ["p1"]
    if outcomes_p2 is not None:
        p2 = RecordingProvider(outcomes=outcomes_p2)
        p2.name = "p2"
        providers["p2"] = p2
        chain.append("p2")
    return UnifiedLLMClient(providers=providers, chain=chain, circuit_threshold=threshold, cooldown_s=cooldown_s), providers


class TestFallback:
    @pytest.mark.asyncio
    async def test_falls_back_to_second_provider(self):
        client, providers = _client(
            [LLMUnavailable("p1", "down")],
            ["from-p2"],
        )
        resp = await client.generate(_req())
        assert resp.text == "from-p2"
        assert len(providers["p1"].requests) == 1
        assert len(providers["p2"].requests) == 1

    @pytest.mark.asyncio
    async def test_all_fail_raises_last_error(self):
        client, _ = _client([LLMTimeout("p1"), LLMTimeout("p1")], [LLMUnavailable("p2")])
        with pytest.raises(LLMUnavailable):
            await client.generate(_req())

    @pytest.mark.asyncio
    async def test_empty_chain_raises_unavailable(self):
        client = UnifiedLLMClient(providers={}, chain=[], transport=__import__("httpx").MockTransport(lambda r: httpx.Response(200)))
        with pytest.raises(LLMUnavailable, match="no LLM provider"):
            await client.generate(_req())


class TestCircuitBreakerUnit:
    def test_opens_after_threshold(self):
        cb = CircuitBreaker(threshold=3, cooldown_s=60)
        assert not cb.is_open("x")
        cb.record_failure("x")
        cb.record_failure("x")
        assert not cb.is_open("x")
        cb.record_failure("x")
        assert cb.is_open("x")

    def test_success_resets(self):
        cb = CircuitBreaker(threshold=3, cooldown_s=60)
        cb.record_failure("x")
        cb.record_failure("x")
        cb.record_success("x")
        cb.record_failure("x")
        cb.record_failure("x")
        assert not cb.is_open("x")

    def test_half_open_after_cooldown(self):
        cb = CircuitBreaker(threshold=1, cooldown_s=0.01)
        cb.record_failure("x")
        assert cb.is_open("x")
        import time

        time.sleep(0.02)
        assert not cb.is_open("x")


class TestCircuitIntegration:
    @pytest.mark.asyncio
    async def test_open_provider_is_skipped_without_http_call(self):
        # threshold 2: two failures open the circuit; third generate() must NOT reach the provider
        client, providers = _client(
            [LLMUnavailable("p1", "down"), LLMUnavailable("p1", "down")],
            threshold=2,
        )
        for _ in range(2):
            with pytest.raises(LLMUnavailable):
                await client.generate(_req())
        assert len(providers["p1"].requests) == 2
        with pytest.raises(LLMUnavailable):
            await client.generate(_req())
        assert len(providers["p1"].requests) == 2  # skipped by breaker

    @pytest.mark.asyncio
    async def test_half_open_retries_provider_after_cooldown(self):
        import time

        client, providers = _client(
            [
                LLMUnavailable("p1", "down"),
                "recovered",
            ],
            threshold=1,
            cooldown_s=0.01,
        )
        with pytest.raises(LLMUnavailable):
            await client.generate(_req())
        time.sleep(0.02)
        resp = await client.generate(_req())
        assert resp.text == "recovered"
        assert len(providers["p1"].requests) == 2

