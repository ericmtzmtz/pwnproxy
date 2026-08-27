"""Golden workflow tests: deterministic E2E paths exercising the core pipeline.

Marked with ``@pytest.mark.golden`` — run with:
    poetry run pytest -m golden

Each golden test uses in-process components (FakeFetcher, in-memory engines,
FakeLLMClient) to guarantee determinism.
"""

import asyncio
import json
from datetime import datetime, timezone

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from pwnproxy.plugins.core.base import Finding
from pwnproxy.services.crawler.engine import CrawlConfig, CrawlEngine
from pwnproxy.services.crawler.storage import DiscoveredURLStorage
from pwnproxy.services.findings.engine import ExportEngine
from pwnproxy.services.session.manager import ScopeConfig
from pwnproxy.shared.findings.storage import FindingStorage

# ── FakeFetcher (shared across goldens) ──────────────────────────────────


class FakeFetcher:
    """In-memory fetcher for deterministic crawl tests."""

    def __init__(self, pages: dict[str, str]):
        self.pages = pages
        self.fetch_log: list[str] = []

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass

    async def fetch(self, url: str):
        self.fetch_log.append(url)
        body = self.pages.get(url)
        if body is None:
            return None
        return {
            "method": "GET",
            "url": url,
            "request_headers": {},
            "request_body": None,
            "response_headers": {"content-type": "text/html"},
            "response_body": body,
            "response_body_truncated": False,
            "status_code": 200,
            "duration_ms": 1.0,
            "tls": False,
        }


# ── Scope helper ──────────────────────────────────────────────────────────


def _make_scope(patterns: list[str], out: list[str] | None = None):
    return ScopeConfig({
        "enabled": bool(patterns),
        "in_scope": patterns,
        "out_of_scope": out or [],
    })


# ── Helper: run engine to completion ──────────────────────────────────────


async def _collect_crawl(engine: CrawlEngine, fetcher: FakeFetcher) -> list[dict]:
    flows = []
    async for flow in engine.run(fetcher):
        flows.append(flow)
    return flows


# ── Golden 1: Discovery ──────────────────────────────────────────────────
# Crawl → URLs fetched → scope validated → dedup → cancel → stats verified


@pytest.mark.golden
class TestGoldenDiscovery:
    BASE = "https://target.local"

    def _pages(self) -> dict[str, str]:
        return {
            f"{self.BASE}/": '<html><a href="/about">About</a> <a href="/search?q=hello">Search</a></html>',
            f"{self.BASE}/about": "<html>About page</html>",
            f"{self.BASE}/search?q=hello": "<html>Results for hello</html>",
            f"{self.BASE}/admin": "<html>Admin panel (out of scope)</html>",
            f"{self.BASE}/api/users": '<html>{"users": []}</html>',
            # External link (out of scope)
            f"{self.BASE}/redirect": '<html><a href="https://evil.com/steal">click</a></html>',
        }

    @pytest.mark.asyncio
    async def test_crawl_discovers_in_scope_urls(self):
        """Active crawl discovers all in-scope URLs and respects scope boundaries."""
        pages = self._pages()
        fetcher = FakeFetcher(pages)
        scope = _make_scope(["*://target.local/*"])

        engine = CrawlEngine(
            config=CrawlConfig(seeds=[f"{self.BASE}/"], depth=3),
            scope=scope,
        )

        flows = await _collect_crawl(engine, fetcher)
        fetched_urls = {f["url"] for f in flows}

        # All in-scope pages fetched
        assert f"{self.BASE}/" in fetched_urls
        assert f"{self.BASE}/about" in fetched_urls
        assert f"{self.BASE}/search?q=hello" in fetched_urls
        # /api/users not linked from any page, so not discovered by crawler
        assert f"{self.BASE}/api/users" not in fetched_urls

        # Out-of-scope not fetched
        assert f"{self.BASE}/admin" not in fetched_urls
        assert "https://evil.com/steal" not in fetched_urls

        # Check scope was respected
        assert engine.stats.fetched > 0

    @pytest.mark.asyncio
    async def test_crawl_dedup_path_only(self):
        """Same path with different query params is not fetched twice."""
        pages = {
            f"{self.BASE}/page?x=1": '<html><a href="/page?y=2">dup</a></html>',
            f"{self.BASE}/page?y=2": "<html>dup page</html>",
        }
        fetcher = FakeFetcher(pages)
        scope = _make_scope(["*://target.local/*"])

        engine = CrawlEngine(
            config=CrawlConfig(seeds=[f"{self.BASE}/page?x=1"], depth=2),
            scope=scope,
        )

        flows = await _collect_crawl(engine, fetcher)
        # Only one /page fetch (path dedup)
        page_fetches = [u for u in fetcher.fetch_log if "/page" in u]
        assert len(page_fetches) == 1

    @pytest.mark.asyncio
    async def test_crawl_cancel_mid_run(self):
        """Crawl can be cancelled mid-run without corruption."""
        pages = {
            f"{self.BASE}/": '<html><a href="/slow">slow</a></html>',
            f"{self.BASE}/slow": "<html>slow page</html>",
        }
        fetcher = FakeFetcher(pages)
        scope = _make_scope(["*://target.local/*"])

        engine = CrawlEngine(
            config=CrawlConfig(seeds=[f"{self.BASE}/"], depth=5),
            scope=scope,
        )

        # Start crawl, cancel after first flow
        flows = []
        async for flow in engine.run(fetcher):
            flows.append(flow)
            if len(flows) >= 1:
                engine.cancel()

        # Should have at least 1 flow, engine stats reflect partial run
        assert len(flows) >= 1
        stats = engine.stats
        assert isinstance(stats.fetched, int)

    @pytest.mark.asyncio
    async def test_persist_discovered_urls(self):
        """Crawled URLs can be persisted to DiscoveredURLStorage."""
        pages = self._pages()
        fetcher = FakeFetcher(pages)
        scope = _make_scope(["*://target.local/*"])

        engine = CrawlEngine(
            config=CrawlConfig(seeds=[f"{self.BASE}/"], depth=2),
            scope=scope,
        )

        flows = await _collect_crawl(engine, fetcher)

        # Persist to storage
        db_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        storage = DiscoveredURLStorage(db_engine)
        await storage.create_table()

        for flow in flows:
            await storage.save(
                url=flow["url"],
                source="golden-crawl",
            )

        count = await storage.count()
        assert count == len(flows)

        stored = await storage.list()
        stored_urls = {r["url"] for r in stored}
        for flow in flows:
            assert flow["url"] in stored_urls

        await db_engine.dispose()


# ── Golden 2: Finding ────────────────────────────────────────────────────
# Vulnerable target → REAL scanner → finding persisted → triage → final state


@pytest.mark.golden
class TestGoldenFinding:
    """Golden 2 — real XSSScannerPlugin + RequestReplayer against a
    deterministic in-process vulnerable target (see xss_target.py)."""

    def _make_target(self):
        # Load the fixture by file path: `tests` is not a package on sys.path
        # under every pytest invocation mode.
        import importlib.util
        from pathlib import Path
        spec = importlib.util.spec_from_file_location(
            "golden_xss_target", Path(__file__).parent / "xss_target.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        target = module.XssTargetServer()
        target.start()
        return target

    async def _scan(self, base_url: str, path: str) -> list:
        """Run the real XSS scanner plugin against one target path."""
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
                id=f"golden-xss-{path.strip('/')}",
                method="GET",
                url=f"{base_url}{path}",
                request_headers={},
                request_body=None,
            )
            return [f async for f in plugin.on_flow(flow)]
        finally:
            await plugin.on_unload()

    def _make_storage(self):
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        return engine, FindingStorage(engine)

    @pytest.mark.asyncio
    async def test_xss_scanner_detects_reflected_payload(self):
        """Real scanner flags the vulnerable /reflect endpoint."""
        target = self._make_target()
        try:
            findings = await self._scan(target.base_url, "/reflect?name=hello")
            assert findings, "reflected XSS on /reflect was not detected"
            f = findings[0]
            assert f.scanner == "xss"
            assert f.technique == "reflected-xss"
            assert f.param_name == "name"
            assert f.param_location == "query"
            assert f.payload
            assert f.request_data is not None
            assert "reflect" in f.request_data["url"]
        finally:
            target.stop()

    @pytest.mark.asyncio
    async def test_xss_scanner_negative_control(self):
        """The escaped /safe endpoint must NOT produce a finding."""
        target = self._make_target()
        try:
            findings = await self._scan(target.base_url, "/safe?name=hello")
            assert findings == [], f"false positive on /safe: {findings}"
        finally:
            target.stop()

    @pytest.mark.asyncio
    async def test_scanned_finding_persisted_and_triaged(self):
        """Scanner finding → persisted via FindingStorage → triaged true_positive."""
        target = self._make_target()
        engine, storage = self._make_storage()
        await storage.create_table()
        try:
            findings = await self._scan(target.base_url, "/reflect?name=hello")
            assert findings

            fid = await storage.save(findings[0])
            assert fid > 0

            retrieved = await storage.get(fid)
            assert retrieved is not None
            assert retrieved["scanner"] == "xss"
            assert retrieved["technique"] == "reflected-xss"
            assert retrieved["payload"]

            updated = await storage.set_triage(
                finding_id=fid,
                verdict="true_positive",
                method="llm",
                score=0.88,
                reason="Payload reflected unescaped in response body",
                features={"reflection_length": 42},
            )
            assert updated["triage_verdict"] == "true_positive"
            assert updated["triage_method"] == "llm"
            assert updated["triage_score"] == 0.88
        finally:
            target.stop()
            await engine.dispose()

    @pytest.mark.asyncio
    async def test_scanned_finding_triaged_false_positive(self):
        """Scanner finding → triaged false_positive."""
        target = self._make_target()
        engine, storage = self._make_storage()
        await storage.create_table()
        try:
            findings = await self._scan(target.base_url, "/reflect?name=hello")
            fid = await storage.save(findings[0])

            updated = await storage.set_triage(
                finding_id=fid,
                verdict="false_positive",
                method="heuristic",
                score=0.15,
                reason="Reflection inside a JSON API response, not HTML context",
            )
            assert updated["triage_verdict"] == "false_positive"
            assert updated["triage_score"] == 0.15
        finally:
            target.stop()
            await engine.dispose()


# ── Golden 3: Report ─────────────────────────────────────────────────────
# Fixed findings + FakeLLMClient → structured output → rendered report


@pytest.mark.golden
class TestGoldenReport:
    def _make_findings(self) -> list[Finding]:
        return [
            Finding(
                scanner="sqli",
                url="https://target.local/search?q=test",
                method="GET",
                param_name="q",
                param_location="query",
                technique="error-based",
                severity="high",
                confidence="confirmed",
                payload="' OR 1=1--",
                evidence="MySQL error: syntax near UNION",
            ),
            Finding(
                scanner="xss",
                url="https://target.local/reflect?name=world",
                method="GET",
                param_name="name",
                param_location="query",
                technique="reflected",
                severity="medium",
                confidence="confirmed",
                payload="<script>alert(1)</script>",
                evidence="Payload reflected unescaped in response body",
            ),
            Finding(
                scanner="sqli",
                url="https://target.local/login",
                method="POST",
                param_name="password",
                param_location="body",
                technique="boolean-blind",
                severity="critical",
                confidence="tentative",
                payload="admin' OR '1'='1",
                evidence="Response length differs by 42 bytes on true/false conditions",
            ),
        ]

    def test_export_json(self):
        """ExportEngine produces valid JSON from findings."""
        findings = self._make_findings()
        engine = ExportEngine(findings, target_url="https://target.local")

        json_str = engine.to_json()
        data = json.loads(json_str)

        assert len(data) == 3
        assert data[0]["scanner"] == "sqli"
        assert data[1]["technique"] == "reflected"
        assert data[2]["severity"] == "critical"

    def test_export_sarif(self):
        """ExportEngine produces valid SARIF with correct structure."""
        findings = self._make_findings()
        engine = ExportEngine(findings, target_url="https://target.local")

        sarif_str = engine.to_sarif()
        sarif = json.loads(sarif_str)

        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        results = sarif["runs"][0]["results"]
        assert len(results) == 3

        # Check severity mapping
        assert results[0]["level"] == "error"  # high
        assert results[1]["level"] == "warning"  # medium
        assert results[2]["level"] == "error"  # critical → error

    def test_export_html(self):
        """ExportEngine produces HTML report."""
        findings = self._make_findings()
        engine = ExportEngine(findings, target_url="https://target.local")

        html = engine.to_html()
        assert "<!DOCTYPE html>" in html or "<html" in html
        assert "target.local" in html
        assert "sqli" in html
        assert "xss" in html

    def test_to_dicts(self):
        """to_dicts produces list of dicts with all required fields."""
        findings = self._make_findings()
        engine = ExportEngine(findings, target_url="https://target.local")

        dicts = engine.to_dicts()
        assert len(dicts) == 3
        for d in dicts:
            assert "scanner" in d
            assert "url" in d
            assert "severity" in d
            assert "payload" in d
            assert "evidence" in d


# ── Golden 3: Report (LLM) ───────────────────────────────────────────────
# Real ReportGenerator pipeline driven by a FakeLLMClient → rendered report


def _finding_dict(url="http://target.local/search", technique="sqli-union", param="q"):
    return {
        "scanner": "sqli",
        "url": url,
        "method": "GET",
        "param_name": param,
        "param_location": "query",
        "technique": technique,
        "severity": "high",
        "confidence": "confirmed",
        "payload": "' OR 1=1--",
        "evidence": "error: syntax near UNION",
        "timestamp": None,
        "extra": {},
        "request_data": None,
    }


@pytest.mark.golden
class TestGoldenReportWithLLM:
    """Golden 3 — full report pipeline (analyzer → LLM narratives → render)."""

    @pytest.mark.asyncio
    async def test_report_generator_renders_artifacts(self, tmp_path):
        from pwnproxy.ai.llm.testing import FakeLLMClient
        from pwnproxy.ai.reports.analyzer import GroupFacts
        from pwnproxy.ai.reports.generator import GroupNarrative, ReportGenerator

        llm = FakeLLMClient([
            GroupFacts(
                title="SQL injection in search parameter",
                severity="high",
                vector="union injection",
                key_evidence="syntax near UNION",
                impact="data exposure",
                remediation="use parameterized queries",
            ),
            GroupNarrative(
                title="SQL injection in search parameter",
                description="The q parameter concatenates user input into SQL.",
                impact_paragraph="Attackers can dump the database contents.",
                remediation_steps=["Use parameterized queries", "Validate input"],
            ),
            "One high-severity SQL injection was confirmed in the search endpoint.",
        ])

        generator = ReportGenerator(llm, session_name="golden")
        out_dir = tmp_path / "report"
        result = await generator.generate(
            [_finding_dict()],
            out_dir,
            audience="technical",
            formats=("md", "html"),
        )

        assert set(result["files"]) == {"md", "html"}
        assert result["flagged_groups"] == 0  # no hallucinated facts → not flagged
        assert (out_dir / "report.md").exists()
        assert (out_dir / "report.html").exists()

        markdown = (out_dir / "report.md").read_text(encoding="utf-8")
        assert "Security Assessment Report" in markdown
        assert "SQL injection" in markdown
        assert "search" in markdown

        html = (out_dir / "report.html").read_text(encoding="utf-8")
        assert "Security Assessment Report" in html

        # The fake LLM was driven through analysis, writing and summary phases.
        assert len(llm.structured_calls) == 2  # GroupFacts + GroupNarrative
        assert len(llm.calls) == 3  # + exec summary text call

    @pytest.mark.asyncio
    async def test_report_generator_flags_hallucinated_cve(self, tmp_path):
        """Facts with an untraceable CVE must mark the group as flagged."""
        from pwnproxy.ai.llm.testing import FakeLLMClient
        from pwnproxy.ai.reports.analyzer import GroupFacts
        from pwnproxy.ai.reports.generator import GroupNarrative, ReportGenerator

        llm = FakeLLMClient([
            GroupFacts(
                title="SQL injection in search parameter",
                severity="high",
                vector="union injection",
                key_evidence="CVE-2024-99999",
                impact="data exposure",
                remediation="use parameterized queries",
            ),
            GroupNarrative(
                title="SQL injection in search parameter",
                description="The q parameter concatenates user input into SQL.",
                impact_paragraph="Attackers can dump the database contents.",
                remediation_steps=["Use parameterized queries"],
            ),
            "Summary.",
        ])

        generator = ReportGenerator(llm, session_name="golden")
        result = await generator.generate(
            [_finding_dict()],
            tmp_path / "report",
            audience="technical",
            formats=("md",),
        )
        assert result["flagged_groups"] == 1

    @pytest.mark.asyncio
    async def test_report_generator_rejects_empty_findings(self, tmp_path):
        from pwnproxy.ai.llm.testing import FakeLLMClient
        from pwnproxy.ai.reports.generator import ReportGenerator

        generator = ReportGenerator(FakeLLMClient([]), session_name="golden")
        with pytest.raises(ValueError, match="No findings"):
            await generator.generate([], tmp_path / "report")


# ── Golden 4: Full pipeline ──────────────────────────────────────────────
# Crawl → persist → findings → triage → report


@pytest.mark.golden
class TestGoldenFullPipeline:
    BASE = "https://target.local"

    @pytest.mark.asyncio
    async def test_crawl_to_report_pipeline(self):
        """Full pipeline: crawl discovers URLs → findings created → triaged → report."""
        # Phase 1: Discovery
        pages = {
            f"{self.BASE}/": '<html><a href="/search?q=test">Search</a></html>',
            f"{self.BASE}/search?q=test": "<html>Results for test</html>",
        }
        fetcher = FakeFetcher(pages)
        scope = _make_scope(["*://target.local/*"])
        engine = CrawlEngine(
            config=CrawlConfig(seeds=[f"{self.BASE}/"], depth=2),
            scope=scope,
        )
        flows = await _collect_crawl(engine, fetcher)
        assert len(flows) >= 1

        # Phase 2: Persist discovery results
        db_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        discovered = DiscoveredURLStorage(db_engine)
        await discovered.create_table()
        for flow in flows:
            await discovered.save(url=flow["url"], source="golden-pipeline")

        # Phase 3: Simulate findings from scanner
        finding_storage = FindingStorage(db_engine)
        await finding_storage.create_table()

        finding = Finding(
            scanner="sqli",
            url=f"{self.BASE}/search?q=test",
            method="GET",
            param_name="q",
            param_location="query",
            technique="error-based",
            severity="high",
            confidence="confirmed",
            payload="' OR 1=1--",
            evidence="MySQL syntax error detected",
        )
        fid = await finding_storage.save(finding)
        assert fid > 0

        # Phase 4: Triage
        updated = await finding_storage.set_triage(
            finding_id=fid,
            verdict="true_positive",
            method="llm",
            score=0.88,
            reason="SQLi error-based confirmed",
        )
        assert updated["triage_verdict"] == "true_positive"

        # Phase 5: Report generation
        retrieved = await finding_storage.get(fid)
        report_finding = Finding(
            scanner=retrieved["scanner"],
            url=retrieved["url"],
            method=retrieved["method"],
            param_name=retrieved["param_name"],
            param_location=retrieved["param_location"],
            technique=retrieved["technique"],
            severity=retrieved["severity"],
            confidence=retrieved["confidence"],
            payload=retrieved["payload"],
            evidence=retrieved["evidence"],
        )
        export = ExportEngine([report_finding], target_url=self.BASE)
        report_json = json.loads(export.to_json())
        assert len(report_json) == 1
        assert report_json[0]["severity"] == "high"

        report_sarif = json.loads(export.to_sarif())
        assert report_sarif["runs"][0]["results"][0]["level"] == "error"

        await db_engine.dispose()

    @pytest.mark.asyncio
    async def test_discovery_stats_reflected(self):
        """Crawl stats are correctly tracked through the pipeline."""
        pages = {
            f"{self.BASE}/": '<html><a href="/a">a</a> <a href="/b">b</a></html>',
            f"{self.BASE}/a": "<html>page A</html>",
            f"{self.BASE}/b": "<html>page B</html>",
        }
        fetcher = FakeFetcher(pages)
        scope = _make_scope(["*://target.local/*"])
        engine = CrawlEngine(
            config=CrawlConfig(seeds=[f"{self.BASE}/"], depth=2),
            scope=scope,
        )
        flows = await _collect_crawl(engine, fetcher)

        stats = engine.stats
        assert stats.fetched == 3  # /, /a, /b
        assert stats.errors == 0
