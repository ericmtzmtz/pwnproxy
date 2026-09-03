"""Structured output: valid, invalid-then-retry-ok, invalid-twice."""
import json
from typing import Literal, Optional

import pytest
from pydantic import BaseModel, Field

from pwnproxy.ai.llm.client import _schema_prompt, extract_json
from pwnproxy.ai.llm.errors import LLMSchemaError
from pwnproxy.ai.llm.models import LLMMessage, LLMRequest
from pwnproxy.ai.llm.testing import FakeLLMClient, RecordingProvider


class Out(BaseModel):
    answer: int


class Sub(BaseModel):
    depth: int = Field(description="depth level")


class Probe(BaseModel):
    title: str = Field(description="A title")
    severity: str = Field(description="One of: critical, high, medium, low, info")
    confidence: float = Field(ge=0.0, le=1.0, description="confidence between 0.0 and 1.0")
    verdict: Literal["true_positive", "false_positive", "uncertain"]
    items: list[str] = Field(description="some strings")
    maybe: Optional[int] = None
    sub: Sub = Field(description="nested")
    weird: dict = Field(description="anything")
    long: str = Field(description="x" * 300)


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


class TestSchemaInjection:
    """generate_structured must teach the backend the output schema via text."""

    @pytest.mark.asyncio
    async def test_initial_call_injects_schema_block(self):
        client, p = _client_with(['{"answer": 42}'])
        await client.generate_structured(_req(), Out)
        system_msgs = [m.content for m in p.requests[0].messages if m.role == "system"]
        joined = "\n".join(system_msgs)
        assert '"answer"' in joined and "(number" in joined

    @pytest.mark.asyncio
    async def test_json_mode_still_forced(self):
        client, p = _client_with(['{"answer": 1}'])
        await client.generate_structured(_req(), Out)
        assert p.requests[0].json_mode is True


class TestSchemaRenderer:
    """The _schema_prompt renderer covers common pydantic shapes."""

    def test_render_all_type_shapes(self):
        out = _schema_prompt(Probe)
        assert '"title" (string)' in out
        assert '"verdict" (one of:' in out
        assert '"items" (list of string)' in out
        assert '"maybe" (number (integer) or null)' in out
        assert '"sub.depth" (number (integer))' in out
        assert '"weird" (object)' in out
        assert '"confidence" (number)' in out
        assert ">= 0.0" in out and "<= 1.0" in out

    def test_long_description_truncated(self):
        out = _schema_prompt(Probe)
        assert ("x" * 300) not in out  # full untruncated blob absent
        assert ("x" * 200) in out  # truncated prefix present

    def test_unknown_type_falls_back_to_string(self):
        class Odd(BaseModel):
            weird: dict = Field(description="anything")
            other: object = Field(description="opaque")

        out = _schema_prompt(Odd)
        assert '"weird" (object)' in out
        assert '"other" (string)' in out  # unknown object type → string

    def test_empty_schema_renders_empty(self):
        class Empty(BaseModel):
            pass

        assert _schema_prompt(Empty) == ""


class TestDisobedientBackend:
    """Regression: FreeLLM model=auto-style backend ignores json_mode and
    returns invented keys first; the retry (now carrying the schema) must
    recover."""

    @pytest.mark.asyncio
    async def test_invented_keys_then_schema_aware_reply(self):
        client, p = _client_with(
            [
                '{"vulnerability": "x", "parameter": "id", "confidence": "high"}',
                '{"answer": 42}',
            ]
        )
        parsed, _ = await client.generate_structured(_req(), Out)
        assert parsed.answer == 42
        assert len(p.requests) == 2
        # second request must contain the schema text for the retry
        retry_sys = " ".join(m.content for m in p.requests[1].messages if m.role == "system")
        assert '"answer"' in retry_sys
        retry_user = " ".join(m.content for m in p.requests[1].messages if m.role == "user")
        assert "invalid" in retry_user


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
