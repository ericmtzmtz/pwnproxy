"""Provider contract: turn an LLMRequest into an LLMResponse via httpx."""
import time
from abc import ABC, abstractmethod
from typing import ClassVar, Optional

import httpx

from pwnproxy.ai.llm.errors import LLMTimeout, LLMUnavailable
from pwnproxy.ai.llm.models import LLMRequest, LLMResponse


class Provider(ABC):
    """HTTP adapter for one backend. Stateless: the shared AsyncClient is injected."""

    name: ClassVar[str] = ""
    default_model: ClassVar[str] = ""

    def __init__(
        self,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout_s: float = 30.0,
    ):
        self.model = model or self.default_model
        self.api_key = api_key
        self.base_url = (base_url or self.default_base_url).rstrip("/")
        self.timeout_s = timeout_s

    @property
    def default_base_url(self) -> str:
        raise NotImplementedError

    @abstractmethod
    async def generate(self, request: LLMRequest, http: httpx.AsyncClient) -> LLMResponse:
        ...

    async def _post(self, http: httpx.AsyncClient, url: str, headers: dict, payload: dict) -> dict:
        start = time.monotonic()
        try:
            resp = await http.post(url, headers=headers, json=payload, timeout=self.timeout_s)
            resp.raise_for_status()
            data = resp.json()
        except httpx.TimeoutException as e:
            raise LLMTimeout(self.name) from e
        except httpx.HTTPStatusError as e:
            raise LLMUnavailable(self.name, f"HTTP {e.response.status_code} from {self.name}") from e
        except httpx.HTTPError as e:
            raise LLMUnavailable(self.name, f"{type(e).__name__}: {e}") from e
        except ValueError as e:
            raise LLMUnavailable(self.name, "response was not valid JSON") from e
        self.last_latency_ms = int((time.monotonic() - start) * 1000)
        return data
