"""Live verification tests against real targets — opt-in, never in CI.

bWAPP  : http://localhost/bWAPP        (default creds bee/bug)
LLM API: custom OpenAI-compatible endpoint configured in ~/.pwnproxy/config.toml

Run with::

    $env:PWNPROXY_LIVE=1; poetry run pytest -m live -v
"""

import json
import os

import httpx
import pytest

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("PWNPROXY_LIVE") != "1",
        reason="live tests require PWNPROXY_LIVE=1 (they hit real external services)",
    ),
]

BWAPP_BASE = "http://localhost/bWAPP"
BWAPP_USER = "bee"
BWAPP_PASS = "bug"


# ── Helpers ──────────────────────────────────────────────────────────────


async def _bwapp_cookie() -> str:
    """Log into bWAPP and return the PHPSESSID cookie value.

    bWAPP's login flow is POST login.php → 302 security_level_set.php
    (applies the security level) → 302 portal.php, so redirects must be
    followed for the session to be usable.

    Falls back to the repo-root cookies.txt if interactive login fails
    (bWAPP session limits kick in quickly on repeated logins).
    """
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
            await client.post(
                f"{BWAPP_BASE}/login.php",
                data={
                    "login": BWAPP_USER,
                    "password": BWAPP_PASS,
                    "security_level": "0",
                    "form": "submit",
                },
            )
            # bWAPP applies the security level in a separate POST step.
            await client.post(
                f"{BWAPP_BASE}/security_level_set.php",
                data={"security_level": "0", "form": "submit"},
            )
            sid = client.cookies.get("PHPSESSID")
            if sid:
                # Sanity check: the session must be able to render a page.
                probe = await client.get(
                    f"{BWAPP_BASE}/xss_get.php?firstname=hello&lastname=world&form=submit"
                )
                if probe.status_code == 200:
                    return sid
    except httpx.HTTPError:
        pass

    cookies_txt = os.path.join(os.path.dirname(__file__), "..", "..", "cookies.txt")
    if os.path.exists(cookies_txt):
        value = open(cookies_txt, encoding="utf-8").read().strip()
        if value:
            return value
    pytest.skip("bWAPP login failed and no cookies.txt fallback available")


async def _scan_xss_get(session_cookie: str) -> list:
    """Run the real XSS scanner plugin against /bWAPP/xss_get.php."""
    from pwnproxy.plugins.core.base import PluginContext
    from pwnproxy.plugins.scanners.xss.plugin import XSSScannerPlugin
    from pwnproxy.shared.models import Flow

    plugin = XSSScannerPlugin(context=PluginContext(config={
        "depth": "fast",
        "evasion_level": "none",
    }))
    await plugin.on_load()
    try:
        flow = Flow(
            id="live-bwapp-xss",
            method="GET",
            url=f"{BWAPP_BASE}/xss_get.php?firstname=hello&lastname=world&form=submit",
            request_headers={
                # bWAPP needs both cookies: session + applied security level.
                "cookie": f"PHPSESSID={session_cookie}; security_level=0",
            },
            request_body=None,
        )
        return [f async for f in plugin.on_flow(flow)]
    finally:
        await plugin.on_unload()


# ── Live: bWAPP XSS ──────────────────────────────────────────────────────


@pytest.mark.live
class TestLiveBwappXss:
    @pytest.mark.asyncio
    async def test_xss_scanner_detects_reflected_xss_in_bwapp(self):
        """Real scanner must flag xss_get.php (low security) on live bWAPP."""
        cookie = await _bwapp_cookie()
        findings = await _scan_xss_get(cookie)
        # The accuracy change separates reflection from execution: a real XSS
        # requires an exploitable breakout. Non-exploitable reflections must
        # only ever surface as low/tentative unescaped-reflection, never as a
        # high/confirmed XSS. bWAPP low security reflects unescaped, so the
        # exploitable reflected-xss must still be present.
        assert any(
            f.param_name in ("firstname", "lastname") and f.technique == "reflected-xss"
            for f in findings
        ), f"unexpected findings: {[f.param_name for f in findings]}"
        for f in findings:
            if f.technique == "unescaped-reflection":
                assert f.severity == "low" and f.confidence == "tentative", (
                    f"unescaped-reflection mis-scored: {f.technique}/{f.severity}/{f.confidence}"
                )

    @pytest.mark.asyncio
    async def test_finding_persists_and_triages(self):
        """Scanned finding survives persistence + triage end-to-end."""
        from sqlalchemy.ext.asyncio import create_async_engine

        from pwnproxy.shared.findings.storage import FindingStorage

        cookie = await _bwapp_cookie()
        findings = await _scan_xss_get(cookie)
        assert findings

        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        storage = FindingStorage(engine)
        await storage.create_table()
        try:
            fid = await storage.save(findings[0])
            assert fid > 0
            updated = await storage.set_triage(
                finding_id=fid,
                verdict="true_positive",
                method="llm",
                score=0.9,
                reason="Live bWAPP reflects the payload unescaped",
            )
            assert updated["triage_verdict"] == "true_positive"
        finally:
            await engine.dispose()


# ── Live: real LLM API ───────────────────────────────────────────────────


@pytest.mark.live
class TestLiveLlmApi:
    @pytest.mark.asyncio
    async def test_real_llm_generates_text(self):
        """UnifiedLLMClient → real endpoint must return a non-empty response."""
        from pwnproxy.ai.llm.models import LLMMessage, LLMRequest
        from pwnproxy.ai.llm.providers import create_client_from_config

        client = create_client_from_config()
        response = await client.generate(LLMRequest(messages=[
            LLMMessage(role="user", content="Reply with exactly the word: PONG"),
        ]))
        assert response.text.strip()
        assert response.provider
        assert response.model

    @pytest.mark.asyncio
    async def test_real_llm_structured_output(self):
        """Real endpoint must satisfy a structured schema (JSON mode path)."""
        from pydantic import BaseModel

        from pwnproxy.ai.llm.models import LLMMessage, LLMRequest
        from pwnproxy.ai.llm.providers import create_client_from_config

        class Verdict(BaseModel):
            answer: int
            confidence: float

        client = create_client_from_config()
        verdict, _resp = await client.generate_structured(
            LLMRequest(
                messages=[LLMMessage(
                    role="user",
                    content="Return JSON with fields: answer=42, confidence=0.99",
                )],
                json_mode=True,
            ),
            Verdict,
        )
        assert verdict.answer == 42
        assert verdict.confidence > 0.5

    @pytest.mark.asyncio
    async def test_report_generator_with_real_llm(self, tmp_path):
        """Full report pipeline driven by the REAL LLM endpoint."""
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "golden"))

        from pwnproxy.ai.llm.providers import create_client_from_config
        from pwnproxy.ai.reports.generator import ReportGenerator

        findings = [{
            "scanner": "xss",
            "url": f"{BWAPP_BASE}/xss_get.php?firstname=hello&lastname=world&form=submit",
            "method": "GET",
            "param_name": "firstname",
            "param_location": "query",
            "technique": "reflected-xss",
            "severity": "medium",
            "confidence": "confirmed",
            "payload": "<script>alert(1)</script>",
            "evidence": "Payload reflected unescaped in the live bWAPP response",
            "timestamp": None,
            "extra": {},
            "request_data": None,
        }]

        generator = ReportGenerator(create_client_from_config(), session_name="live-bwapp")
        out_dir = tmp_path / "report"
        result = await generator.generate(findings, out_dir, audience="technical", formats=("md",))
        assert "md" in result["files"]
        report = (out_dir / "report.md").read_text(encoding="utf-8")
        assert "Security Assessment Report" in report
        assert "xss" in report.lower()
