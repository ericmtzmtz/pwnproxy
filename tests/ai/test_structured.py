"""Structured output: valid, invalid-then-retry-ok, invalid-twice."""
import json

import pytest
from pydantic import BaseModel

from pwnproxy.ai.llm.client import extract_json
from pwnproxy.ai.llm.errors import LLMSchemaError
from pwnproxy.ai.llm.models import LLMMessage, LLMRequest
from pwnproxy.ai.llm.testing import FakeLLMClient, RecordingProvider


class Out(BaseModel):
    answer: int


def _client_with(outcomes: list) -> tuple:
    p = RecordingProvider(outcomes=outcomes)
    p.name = "fake-provider"
    from pwnproxy.ai.llm.client import UnifiedLLMClient

    client = UnifiedLLMClient(providers={"fake-provider": p}, chain=["fake-provider"])
    return client, p


def _req() -> LLMRequest:
    return LLMRequest(messages=[LLMMessage(role="user", content="give me json")])


class TestExtractJson:
    def test_plain(self):
        assert json.loads(extract_json('{"a":1}')) == {"a": 1}

    def test_fenced(self):
        assert json.loads(extract_json('```json\n{"a":1}\n```')) == {"a": 1}

    def test_prose_wrapped(self):
        assert json.loads(extract_json('Sure! Here it is: {"a": 1} hope that helps')) == {"a": 1}


class TestGenerateStructured:
    @pytest.mark.asyncio
    async def test_valid_first_try(self):
        client, p = _client_with(['{"answer": 42}'])
        parsed, resp = await client.generate_structured(_req(), Out)
        assert parsed.answer == 42 and resp.provider == "fake-provider"
        assert len(p.requests) == 1

    @pytest.mark.asyncio
    async def test_json_mode_forced_on_request(self):
        client, p = _client_with(['{"answer": 1}'])
        await client.generate_structured(_req(), Out)
        assert p.requests[0].json_mode is True

    @pytest.mark.asyncio
    async def test_invalid_then_retry_ok_injects_feedback(self):
        client, p = _client_with(["this is not json", '{"answer": 7}'])
        parsed, _ = await client.generate_structured(_req(), Out)
        assert parsed.answer == 7
        assert len(p.requests) == 2
        roles = [m.role for m in p.requests[1].messages]
        assert roles.count("assistant") == 1  # raw bad response echoed back
        feedback_msgs = [m for m in p.requests[1].messages if m.role == "user" and "invalid" in m.content]
        assert feedback_msgs, "retry must include validation feedback"

    @pytest.mark.asyncio
    async def test_invalid_twice_raises_schema_error(self):
        client, p = _client_with(["nope", 'also {"wrong": "shape"}'])
        with pytest.raises(LLMSchemaError):
            await client.generate_structured(_req(), Out)
        assert len(p.requests) == 2

    @pytest.mark.asyncio
    async def test_schema_violation_counts_as_invalid(self):
        client, _ = _client_with(['{"answer": "not-an-int"}', '{"answer": 3}'])
        parsed, _ = await client.generate_structured(_req(), Out)
        assert parsed.answer == 3


class TestFakeLLMClient:
    @pytest.mark.asyncio
    async def test_scripted_sequence_and_recording(self):
        fake = FakeLLMClient(["first", LLMSchemaError("boom")])
        r1 = await fake.generate(_req())
        assert r1.text == "first"
        with pytest.raises(LLMSchemaError):
            await fake.generate(_req())
        assert len(fake.calls) == 2

    @pytest.mark.asyncio
    async def test_structured_with_model_payload(self):
        fake = FakeLLMClient([Out(answer=5)])
        parsed, _ = await fake.generate_structured(_req(), Out)
        assert parsed.answer == 5
