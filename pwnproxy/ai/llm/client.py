"""UnifiedLLMClient: provider chain with fallback, circuit breaker, structured output."""
import asyncio
import json
import logging
import re
import time
from typing import Any, Literal, Optional, Protocol, TypeVar, Union, get_args, get_origin

import httpx
from pydantic import BaseModel, ValidationError

from pwnproxy.ai.llm.errors import LLMRateLimited, LLMSchemaError, LLMTimeout, LLMUnavailable
from pwnproxy.ai.llm.models import LLMMessage, LLMRequest, LLMResponse
from pwnproxy.ai.llm.usage import UsageLedger

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

_JSON_INSTRUCTION = (
    "Return ONLY a single valid JSON object that conforms to the requested schema. "
    "No prose, no markdown fences."
)

# Longest description we inject into a schema prompt; longer ones are truncated.
_MAX_DESC_CHARS = 200


# ---------------------------------------------------------------------------
# Schema → prompt rendering
#
# `generate_structured` validates output against a Pydantic model, but many
# backends (routers like FreeLLM model=auto, Anthropic, weak Ollama formats)
# ignore the native `response_format`/`format=json` and therefore never learn
# which keys the schema expects. We inject a text description of the schema
# derived from the Pydantic model so every backend sees the exact keys/types.
# ---------------------------------------------------------------------------


def _type_label(annotation: Any, *, flatten_nested: bool = True) -> str:
    """Human label for a Pydantic field annotation (e.g. ``list of strings``)."""
    origin = get_origin(annotation)
    if annotation is str:
        return "string"
    if annotation is int:
        return "number (integer)"
    if annotation is float:
        return "number"
    if annotation is bool:
        return "boolean"
    if annotation is dict or origin is dict:
        return "object"
    if origin is list:
        inner = get_args(annotation)[0] if get_args(annotation) else Any
        return f"list of {_type_label(inner) if inner is not Any else 'values'}"
    if origin is Literal:
        choices = ", ".join(repr(a) for a in get_args(annotation))
        return f"one of: {choices}"
    if origin is Union:
        parts = [_type_label(a, flatten_nested=flatten_nested) for a in get_args(annotation)]
        if type(None) in get_args(annotation):
            non_none = [
                a for a in get_args(annotation) if a is not type(None)
            ]
            if len(non_none) == 1:
                return f"{_type_label(non_none[0], flatten_nested=flatten_nested)} or null"
        return " or ".join(parts)
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        if flatten_nested:
            return "object"
        return "object"
    return "string"


def _field_constraints_suffix(field: Any) -> str:
    """Render numeric/length constraints from pydantic v2 field metadata."""
    hints: list[str] = []
    for meta in getattr(field, "metadata", []) or []:
        ge = getattr(meta, "ge", None)
        le = getattr(meta, "le", None)
        gt = getattr(meta, "gt", None)
        lt = getattr(meta, "lt", None)
        max_len = getattr(meta, "max_length", None)
        min_len = getattr(meta, "min_length", None)
        if ge is not None:
            hints.append(f">= {ge}")
        if gt is not None:
            hints.append(f"> {gt}")
        if le is not None:
            hints.append(f"<= {le}")
        if lt is not None:
            hints.append(f"< {lt}")
        if min_len is not None:
            hints.append(f"min {min_len} chars")
        if max_len is not None:
            hints.append(f"max {max_len} chars")
    return f" ({'; '.join(hints)})" if hints else ""


def _schema_lines(schema: type[BaseModel], *, prefix: str = "") -> list[str]:
    """Flatten a Pydantic model into ``"key.subkey" (type): description`` lines.

    Nested BaseModel fields are flattened with dotted keys so the prompt stays
    linear (no nested object syntax to confuse weak backends).
    """
    lines: list[str] = []
    for name, field in schema.model_fields.items():
        full = f"{prefix}{name}"
        annotation = field.annotation
        desc = (field.description or "").strip()
        if desc and len(desc) > _MAX_DESC_CHARS:
            desc = desc[:_MAX_DESC_CHARS].rstrip() + "…"
        # Recurse into nested BaseModels so their fields come out as dotted keys.
        # Containers (list[Sub], Optional[Sub], Literal, etc.) are rendered flat.
        origin = get_origin(annotation)
        if origin is None and isinstance(annotation, type) and issubclass(annotation, BaseModel):
            lines.extend(_schema_lines(annotation, prefix=f"{full}."))
            continue
        label = _type_label(annotation)
        rendered = f'"{full}" ({label})'
        lines.append(f'- {rendered}{_field_constraints_suffix(field)}' + (f": {desc}" if desc else ""))
    return lines


def _schema_prompt(schema: type[BaseModel]) -> str:
    """Render the output-schema block injected into structured calls."""
    try:
        lines = _schema_lines(schema)
        if not lines:
            return ""
        body = "\n".join(lines)
        return (
            "Output JSON object with EXACTLY these keys (do not add, rename or omit any):\n"
            f"{body}"
        )
    except Exception:
        logger.debug("could not render schema for %s", schema, exc_info=True)
        return ""


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

    def circuit_state(self, provider: str) -> str:
        """Return 'open', 'closed', or 'half-open' for a provider.

        'half-open' means: cooldown expired (_opened_at still set) and there
        are recorded failures, so the provider is being tested. record_success()
        clears _opened_at (→ closed); record_failure() above threshold re-opens.
        """
        if self.is_open(provider):
            return "open"
        opened_at = self._opened_at.get(provider)
        if opened_at is not None and self._failures.get(provider, 0) > 0:
            return "half-open"
        return "closed"


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
        rate_limit_retries: int = 2,
    ):
        self._providers = providers
        self._chain = chain
        self._ledger = ledger
        self.circuit = CircuitBreaker(circuit_threshold, cooldown_s)
        self._http = httpx.AsyncClient(transport=transport) if transport else httpx.AsyncClient()
        # How many times to retry the SAME provider on transient rate-limit
        # (HTTP 429 / 5xx) before falling through the chain.
        self._rate_limit_retries = rate_limit_retries

    @property
    def chain(self) -> list[str]:
        return list(self._chain)

    def _next_candidate(self, after: str) -> str:
        """Look ahead in chain to find the next provider that would actually be tried."""
        names = list(self._chain)
        try:
            idx = names.index(after)
        except ValueError:
            return ""
        for n in names[idx + 1:]:
            provider = self._providers.get(n)
            if provider is not None and not self.circuit.is_open(n):
                return n
        return ""

    def _summary(self, request: LLMRequest) -> str:
        last_user = next((m.content for m in reversed(request.messages) if m.role == "user"), "")
        return last_user

    async def generate(
        self,
        request: LLMRequest,
        *,
        workflow: str = "",
        operation: str = "",
        schema_retry: int = 0,
    ) -> LLMResponse:
        last_error: Exception | None = None
        fallback_from: str = ""
        for name in self._chain:
            provider = self._providers.get(name)
            if provider is None or self.circuit.is_open(name):
                continue
            circuit = self.circuit.circuit_state(name)
            try:
                resp = await self._try_provider(provider, name, request, workflow, operation, schema_retry, circuit)
                self.circuit.record_success(name)
                if self._ledger is not None:
                    await self._ledger.record_ok(
                        resp, self._summary(request),
                        workflow=workflow, operation=operation,
                        fallback_from=fallback_from, circuit_state=circuit,
                        schema_retry=schema_retry,
                    )
                return resp
            except (LLMTimeout, LLMUnavailable) as e:
                self.circuit.record_failure(name)
                last_error = e
                logger.warning("LLM provider %s failed: %s (falling through chain)", name, e)
                if self._ledger is not None:
                    status = "timeout" if isinstance(e, LLMTimeout) else "error"
                    await self._ledger.record_error(
                        name, status, str(e), self._summary(request),
                        workflow=workflow, operation=operation,
                        fallback_from=fallback_from,
                        fallback_to=self._next_candidate(name),
                        circuit_state=circuit,
                        schema_retry=schema_retry,
                    )
                fallback_from = name
        if last_error is not None:
            raise last_error
        raise LLMUnavailable("-", "no LLM provider configured (set an api_key or install/run Ollama)")

    async def _try_provider(
        self, provider, name: str, request: LLMRequest, workflow: str, operation: str,
        schema_retry: int, circuit_state: str,
    ) -> LLMResponse:
        """Call one provider, retrying on transient rate-limit (429/5xx) with backoff."""
        attempt = 0
        while True:
            try:
                return await provider.generate(request, self._http)
            except LLMRateLimited as e:
                attempt += 1
                if attempt > self._rate_limit_retries:
                    raise LLMUnavailable(name, f"rate limited after {attempt} attempts ({e})") from e
                wait = e.retry_after_s or float(attempt) * 2.0  # backoff: 2s, 4s
                logger.info("LLM provider %s rate limited (attempt %d/%d); retrying in %.1fs",
                            name, attempt, self._rate_limit_retries, wait)
                if self._ledger is not None:
                    await self._ledger.record_error(
                        name, "rate_limit", str(e), self._summary(request),
                        workflow=workflow, operation=operation,
                        fallback_from="", fallback_to=name,
                        circuit_state=circuit_state, schema_retry=schema_retry,
                    )
                await asyncio.sleep(wait)

    async def generate_structured(
        self,
        request: LLMRequest,
        schema: type[T],
        *,
        workflow: str = "",
        operation: str = "",
    ) -> tuple[T, "LLMResponse"]:
        first = request.model_copy(update={"json_mode": True})
        schema_block = _schema_prompt(schema)
        # System messages appended: the concrete output schema first, then the
        # generic JSON-only instruction. Both are idempotent guards — the native
        # `response_format`/`format=json` stays as the provider-level hint, while
        # the schema text teaches backends that ignore JSON mode which keys to
        # emit.
        messages = list(first.messages)
        if schema_block:
            messages.append(LLMMessage(role="system", content=schema_block))
        if not any(m.role == "system" and _JSON_INSTRUCTION in m.content for m in messages):
            messages.append(LLMMessage(role="system", content=_JSON_INSTRUCTION))
        first = first.model_copy(update={"messages": messages})

        resp = await self.generate(first, workflow=workflow, operation=operation)
        parsed = self._validate(resp.text, schema)
        if parsed is not None:
            return parsed, resp

        feedback = LLMSchemaError("invalid JSON/schema", raw_text=resp.text)
        # The retry re-sends the full message list (original context + injected
        # schema system messages) plus the bad assistant output and a feedback
        # turn, so a backend that guessed wrong keys is told exactly what to
        # emit this time without losing the grounding context.
        retry_request = first.model_copy(
            update={
                "messages": [
                    *first.messages,
                    LLMMessage(role="assistant", content=resp.text),
                    LLMMessage(
                        role="user",
                        content=(
                            f"Your previous response was invalid: {feedback}\n"
                            "It must be a single JSON object with the exact keys and "
                            "types described in the system message.\n"
                            "Respond again with ONLY the corrected JSON object."
                        ),
                    ),
                ]
            }
        )
        resp2 = await self.generate(retry_request, workflow=workflow, operation=operation, schema_retry=1)
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
