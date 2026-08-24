"""Config parsing: [ai] section of config.toml + PWNPROXY_AI_* env overrides."""
from pathlib import Path

import pytest

from pwnproxy.ai.llm.config import load_llm_config
from pwnproxy.ai.llm.errors import LLMConfigError
from pwnproxy.ai.llm.usage import UsageLedger, default_ledger_engine
from pwnproxy.ai.llm.models import LLMResponse


def _write_config(tmp_path: Path, content: str) -> Path:
    (tmp_path / "config.toml").write_text(content, encoding="utf-8")
    return tmp_path


class TestLoadLLMConfig:
    def test_defaults_when_no_file(self, tmp_path, monkeypatch):
        monkeypatch.delenv("PWNPROXY_AI_PROVIDER", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        s = load_llm_config(config_dir=tmp_path)
        assert s.provider is None
        assert s.timeout_s == 30.0
        assert s.circuit_threshold == 3

    def test_toml_section_parsed(self, tmp_path, monkeypatch):
        monkeypatch.delenv("PWNPROXY_AI_PROVIDER", raising=False)
        _write_config(tmp_path, """
[ai]
provider = "openai"
timeout_s = 12.5
circuit_threshold = 5

[ai.openai]
api_key = "sk-from-file"
model = "gpt-4o"
""")
        s = load_llm_config(config_dir=tmp_path)
        assert s.provider == "openai"
        assert s.timeout_s == 12.5
        assert s.openai.api_key == "sk-from-file"
        assert s.openai.model == "gpt-4o"

    def test_env_overrides_toml(self, tmp_path, monkeypatch):
        _write_config(tmp_path, '[ai]\nprovider = "openai"\n')
        monkeypatch.setenv("PWNPROXY_AI_PROVIDER", "anthropic")
        monkeypatch.setenv("PWNPROXY_AI_OPENAI_API_KEY", "env-key")
        s = load_llm_config(config_dir=tmp_path)
        assert s.provider == "anthropic"
        assert s.openai.api_key == "env-key"

    def test_fallback_chain_comma_string(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PWNPROXY_AI_FALLBACK_CHAIN", "ollama, openai")
        s = load_llm_config(config_dir=tmp_path)
        assert s.fallback_chain == ["ollama", "openai"]

    def test_unknown_provider_rejected(self, tmp_path, monkeypatch):
        _write_config(tmp_path, '[ai]\nprovider = "skynet"\n')
        with pytest.raises(LLMConfigError):
            load_llm_config(config_dir=tmp_path)


@pytest.mark.asyncio
async def test_ledger_records_ok_and_error(tmp_path):
    import sqlalchemy.ext.asyncio as sa_async

    engine = sa_async.create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'usage.db'}")
    ledger = UsageLedger(engine)
    await ledger.record_ok(LLMResponse(text="t", provider="ollama", model="llama3.2", input_tokens=3, output_tokens=4, latency_ms=9), "sum")
    await ledger.record_error("openai", "error", "HTTP 503", "sum2")
    from sqlalchemy import select
    from pwnproxy.ai.llm.usage import UsageRecordORM

    async with sa_async.AsyncSession(engine) as session:
        rows = (await session.execute(select(UsageRecordORM).order_by(UsageRecordORM.id))).scalars().all()
    assert len(rows) == 2
    assert rows[0].status == "ok" and rows[0].input_tokens == 3 and rows[0].request_summary == "sum"
    assert rows[1].status == "error" and rows[1].provider == "openai" and "503" in rows[1].error
