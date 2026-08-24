"""LLM-judge for gray-zone findings (v1)."""
import logging
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from pwnproxy.ai.llm.client import UnifiedLLMClient
from pwnproxy.ai.llm.models import LLMMessage, LLMRequest

logger = logging.getLogger(__name__)

_PROMPT_PATH = Path(__file__).parent / "prompts" / "judge_v1.txt"


class JudgeVerdict(BaseModel):
    verdict: Literal["true_positive", "false_positive", "uncertain"]
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str


class LLMJudge:
    def __init__(self, client: UnifiedLLMClient, model: str | None = None):
        self._client = client
        self._model = model

    @property
    def prompt_version(self) -> str:
        return "judge_v1"

    async def evaluate(self, finding_row: dict, features: dict | None = None) -> JudgeVerdict:
        template = _PROMPT_PATH.read_text(encoding="utf-8")
        summary = {
            k: finding_row.get(k)
            for k in ("id", "scanner", "url", "method", "param_name", "param_location",
                      "technique", "severity", "confidence", "payload", "evidence")
            if k in finding_row
        }
        if features:
            summary["features"] = features
        prompt = template.replace("{{finding}}", repr(summary))
        request = LLMRequest(
            messages=[LLMMessage(role="user", content=prompt)],
            model=self._model,
            temperature=0.0,
            max_tokens=256,
            json_mode=True,
        )
        verdict, _resp = await self._client.generate_structured(request, JudgeVerdict)
        logger.info("triage judge finding=%s -> %s (%.2f)", finding_row.get("id"), verdict.verdict, verdict.confidence)
        return verdict
