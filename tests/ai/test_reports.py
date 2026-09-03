"""Report generation: analyzer units, E2E with FakeLLMClient, anti-hallucination, persistence."""
import asyncio
import importlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.requests import Request as StarletteRequest
from starlette.responses import FileResponse

from pwnproxy.ai.llm.testing import FakeLLMClient
from pwnproxy.ai.reports.analyzer import (
    chunk,
    dedup_findings,
    extract_group_facts,
    risk_aggregates,
    sanitize_facts,
    strip_untraceable_cves,
    GroupFacts,
)
from pwnproxy.ai.reports.generator import GroupNarrative, ReportGenerator
from pwnproxy.ai.reports.render import render_pdf
from pwnproxy.services.session.store import TaskStore
from pwnproxy.shared.findings.storage import FindingStorage
from pwnproxy.shared.task_model import create_task_engine, init_task_db
reports_rest = importlib.import_module("pwnproxy.transport.rest.reports")


@pytest.fixture(autouse=True)
def _dispose_engines():
    """Dispose every aiosqlite engine a test creates via create_task_engine.

    Engines left alive keep their ``_connection_worker_thread`` running; when
    pytest-asyncio closes the test's event loop the worker wakes up on a closed
    loop and emits "Event loop is closed" teardown noise in CI (many threads).
    """
    import sys
    _mod = sys.modules[__name__]
    _orig = _mod.create_task_engine
    created: list = []

    def _tracked_create(*args, **kwargs):
        engine = _orig(*args, **kwargs)
        created.append(engine)
        return engine

    _mod.create_task_engine = _tracked_create
    try:
        yield
    finally:
        _mod.create_task_engine = _orig
        for engine in created:
            try:
                asyncio.run(engine.dispose())
            except Exception:
                pass


def _finding(url="http://target.local/search", technique="sqli-union", param="q",
             severity="high", payload="' OR 1=1--", evidence="error: syntax near UNION"):
    return {
        "scanner": "sqli",
        "url": url,
        "method": "GET",
        "param_name": param,
        "param_location": "query",
        "technique": technique,
        "severity": severity,
        "confidence": "confirmed",
        "payload": payload,
        "evidence": evidence,
        "timestamp": None,
        "extra": {},
        "request_data": {"request": "GET /search?q=x HTTP/1.1"},
    }


def _facts(i: int, vector="union injection") -> GroupFacts:
    return GroupFacts(
        title=f"Issue {i}",
        severity="high",
        vector=vector,
        key_evidence="syntax near UNION",
        impact="data exposure",
        remediation="use parameterized queries",
    )


def _narrative(i: int) -> GroupNarrative:
    return GroupNarrative(
        title=f"Issue {i}",
        description=f"Triggers when param q receives payload variant {i}",
        impact_paragraph="Attacker can read arbitrary data",
        remediation_steps=["Encode output", "Validate input"],
    )


class TestDedup:
    def test_same_key_collapses_with_payload_consolidation(self):
        raw = [
            _finding(payload="' OR 1=1--"),
            _finding(payload="' UNION SELECT NULL--"),
            _finding(payload="' OR 1=1--"),
        ]
        groups = dedup_findings(raw)
        assert len(groups) == 1
        assert groups[0]["occurrences"] == 3
        assert groups[0]["payloads"] == ["' OR 1=1--", "' UNION SELECT NULL--"]

    def test_different_param_stays_separate(self):
        raw = [_finding(param="q"), _finding(param="page")]
        assert len(dedup_findings(raw)) == 2

    def test_worst_severity_and_confidence_win(self):
        raw = [
            _finding(severity="low", evidence="a"),
            dict(_finding(severity="medium", evidence="b"), confidence="confirmed"),
            _finding(severity="critical", evidence="c"),
        ]
        group = dedup_findings(raw)[0]
        assert group["severity"] == "critical"
        assert group["confidence"] == "confirmed"


class TestRiskAggregates:
    def test_counts_hosts_and_max_severity(self):
        raw = [
            _finding(severity="critical"),
            _finding(url="http://other.local/x", severity="low"),
            _finding(),
        ]
        agg = risk_aggregates(dedup_findings(raw), raw_count=len(raw))
        assert agg["raw_findings"] == 3
        assert agg["deduplicated_groups"] == 2
        assert agg["by_severity"] == {"critical": 1, "low": 1}
        assert agg["max_severity"] == "critical"
        assert set(agg["affected_hosts"]) == {"target.local", "other.local"}
        assert agg["scanners"] == {"sqli": 2}


class TestChunking:
    def test_chunks_of_eight(self):
        chunks = chunk(list(range(20)))
        assert [len(c) for c in chunks] == [8, 8, 4]

    def test_single_chunk_for_small_sets(self):
        assert len(chunk([1, 2, 3])) == 1


class TestAntiHallucination:
    def test_invented_cve_is_stripped_and_flagged(self):
        facts = {
            "title": "SQL injection",
            "vector": "Exploits CVE-2023-99999 via parameter q",
            "key_evidence": "syntax near UNION",
            "impact": "Data access per CVE-2023-99999",
            "remediation": "Use parameterized queries",
        }
        clean, flagged = sanitize_facts(facts, _finding())
        assert flagged is True
        assert "CVE-2023-99999" not in json.dumps(clean)
        assert "[unverified reference removed]" in clean["vector"]

    def test_traceable_cve_survives(self):
        evidence = "banner shows CVE-2021-44228 affected log4j"
        clean, flagged = sanitize_facts(
            {"vector": f"Matches {evidence}", "impact": "RCE possible"},
            _finding(evidence=evidence),
        )
        assert flagged is False
        assert "CVE-2021-44228" in clean["vector"]

    def test_strip_helper_reports_removal(self):
        text, removed = strip_untraceable_cves("see CVE-2020-1234 now", "no cve here")
        assert removed is True
        assert "CVE-2020-1234" not in text


@pytest.mark.asyncio
async def test_extract_group_facts_populates_groups():
    llm = FakeLLMClient([_facts(0)])
    groups = dedup_findings([_finding()])
    await extract_group_facts(llm, groups)
    assert groups[0]["facts"]["title"] == "Issue 0"
    assert groups[0]["flagged"] is False


class TestEmptySession:
    @pytest.mark.asyncio
    async def test_generator_fails_before_any_llm_call(self, tmp_path):
        llm = FakeLLMClient([])
        gen = ReportGenerator(llm, session_name="demo")
        with pytest.raises(ValueError, match="No findings"):
            await gen.generate([], tmp_path / "out")
        assert llm.calls == []
        assert llm.structured_calls == []

    @pytest.mark.asyncio
    async def test_endpoint_409_without_findings(self, tmp_path):
        engine = create_task_engine(str(tmp_path / "tasks.db"))
        await init_task_db(engine)
        storage = FindingStorage(engine)
        await storage.create_table()
        store = TaskStore(engine)
        await store.init()
        mgr = SimpleNamespace(has_active_session=True, active_name="demo", get_scanner_engine=lambda: engine, task_store=store)
        app = SimpleNamespace(state=SimpleNamespace(session_manager=mgr, llm_client=FakeLLMClient([])))
        request = StarletteRequest({"type": "http", "app": app})
        with pytest.raises(HTTPException) as exc:
            await reports_rest.generate_report(request, reports_rest.ReportGenerateRequest())
        assert exc.value.status_code == 409
        assert await store.list() == []


async def _seed_findings(engine, findings):
    storage = FindingStorage(engine)
    await storage.create_table()
    for f in findings:
        await storage.save(SimpleNamespace(**f))


async def _wait_terminal(store, task_id, timeout_s=5.0):
    deadline = asyncio.get_event_loop().time() + timeout_s
    while asyncio.get_event_loop().time() < deadline:
        task = await store.get(task_id)
        if task and task["status"] in ("completed", "failed", "cancelled"):
            return task
        await asyncio.sleep(0.05)
    raise AssertionError("report task did not reach terminal state in time")


@pytest.mark.asyncio
async def test_full_pipeline_artifacts_and_downloads(tmp_path, monkeypatch):
    sessions_root = tmp_path / "sessions"
    monkeypatch.setattr(reports_rest, "SESSIONS_ROOT", sessions_root)

    engine = create_task_engine(str(tmp_path / "tasks.db"))
    await init_task_db(engine)
    findings = [
        _finding(),
        _finding(payload="' UNION SELECT NULL--"),
        _finding(url="http://target.local/admin", severity="critical"),
    ]
    await _seed_findings(engine, findings)

    store = TaskStore(engine)
    await store.init()
    llm = FakeLLMClient([
        _facts(0),
        _facts(1),
        _narrative(0),
        _narrative(1),
        "Executive paragraph one. Executive paragraph two.",
    ])
    mgr = SimpleNamespace(has_active_session=True, active_name="demo", get_scanner_engine=lambda: engine, task_store=store)
    request = StarletteRequest({"type": "http", "app": SimpleNamespace(state=SimpleNamespace(session_manager=mgr, llm_client=llm))})

    resp = await reports_rest.generate_report(
        request, reports_rest.ReportGenerateRequest(audience="technical", formats=["md", "html"])
    )
    task = await _wait_terminal(store, resp["task_id"])

    assert task["status"] == "completed", task.get("error")
    assert task["progress"] == 100
    result = task["result"]
    assert result["files"] == {"md": "report.md", "html": "report.html"}
    assert result["audience"] == "technical"
    assert result["aggregates"]["deduplicated_groups"] == 2

    report_md = sessions_root / result["report_dir"] / "report.md"
    report_html = sessions_root / result["report_dir"] / "report.html"
    assert report_md.is_file() and report_html.is_file()
    md_text = report_md.read_text(encoding="utf-8")
    html_text = report_html.read_text(encoding="utf-8")
    assert "# Security Assessment Report" in md_text
    assert "Executive paragraph one." in md_text
    assert "GET /search?q=x HTTP/1.1" in md_text  # request_data appendix rendered
    assert "<!DOCTYPE html>" in html_text and "Issue" in html_text

    dl_md = await reports_rest.download_report(resp["task_id"], request, format="md")
    dl_html = await reports_rest.download_report(resp["task_id"], request, format="html")
    assert isinstance(dl_md, FileResponse) and Path(dl_md.path).is_file()
    assert isinstance(dl_html, FileResponse)

    with pytest.raises(HTTPException) as missing:
        await reports_rest.download_report(resp["task_id"], request, format="pdf")
    assert missing.value.status_code == 404


@pytest.mark.asyncio
async def test_flagged_llm_inventions_never_reach_the_artifact(tmp_path, monkeypatch):
    sessions_root = tmp_path / "sessions"
    monkeypatch.setattr(reports_rest, "SESSIONS_ROOT", sessions_root)

    engine = create_task_engine(str(tmp_path / "tasks2.db"))
    await init_task_db(engine)
    await _seed_findings(engine, [_finding()])
    store = TaskStore(engine)
    await store.init()

    hallucinated = GroupFacts(
        title="SQL injection",
        severity="high",
        vector="Exploits CVE-2099-00001 in the search parameter",
        key_evidence="syntax near UNION",
        impact="Full takeover per CVE-2099-00001",
        remediation="parameterize queries",
    )
    llm = FakeLLMClient([hallucinated, _narrative(0), "Summary text."])
    mgr = SimpleNamespace(has_active_session=True, active_name="demo", get_scanner_engine=lambda: engine, task_store=store)
    request = StarletteRequest({"type": "http", "app": SimpleNamespace(state=SimpleNamespace(session_manager=mgr, llm_client=llm))})

    resp = await reports_rest.generate_report(request, reports_rest.ReportGenerateRequest())
    task = await _wait_terminal(store, resp["task_id"])
    assert task["status"] == "completed", task.get("error")

    report_md = sessions_root / task["result"]["report_dir"] / "report.md"
    text = report_md.read_text(encoding="utf-8")
    assert "CVE-2099-00001" not in text
    assert "unverified LLM references" in text
    assert task["result"]["flagged_groups"] == 1


@pytest.mark.asyncio
async def test_report_downloadable_after_server_restart(tmp_path, monkeypatch):
    sessions_root = tmp_path / "sessions"
    monkeypatch.setattr(reports_rest, "SESSIONS_ROOT", sessions_root)

    db_file = str(tmp_path / "tasks.db")
    engine = create_task_engine(db_file)
    await init_task_db(engine)
    await _seed_findings(engine, [_finding()])

    store = TaskStore(engine)
    await store.init()
    llm = FakeLLMClient([_facts(0), _narrative(0), "Summary."])
    mgr = SimpleNamespace(has_active_session=True, active_name="demo", get_scanner_engine=lambda: engine, task_store=store)
    request = StarletteRequest({"type": "http", "app": SimpleNamespace(state=SimpleNamespace(session_manager=mgr, llm_client=llm))})

    resp = await reports_rest.generate_report(request, reports_rest.ReportGenerateRequest())
    task = await _wait_terminal(store, resp["task_id"])
    assert task["status"] == "completed"

    restarted_store = TaskStore(create_task_engine(db_file))
    await restarted_store.init()
    restarted_app = SimpleNamespace(state=SimpleNamespace(task_store=restarted_store))
    restarted_request = StarletteRequest({"type": "http", "app": restarted_app})

    dl = await reports_rest.download_report(resp["task_id"], restarted_request, format="md")
    assert isinstance(dl, FileResponse)
    assert Path(dl.path).is_file()


class TestPdfOptional:
    def test_missing_weasyprint_gives_actionable_error(self, tmp_path):
        pytest.importorskip.__doc__
        try:
            import weasyprint  # noqa: F401

            pytest.skip("weasyprint installed; graceful-failure path not exercised")
        except ImportError:
            pass
        except OSError:
            pytest.skip("weasyprint installed (native libs missing); not-installed path not exercised")
        with pytest.raises(RuntimeError, match=r"pwnproxy\[reports-pdf\]"):
            render_pdf("<html><body>x</body></html>", tmp_path / "out.pdf")

    def test_weasyprint_native_libs_missing_gives_actionable_error(self, tmp_path):
        """Installed but GTK/Pango DLLs absent (Windows) → OSError at import must
        surface a GTK-specific actionable message, not a generic ImportError one."""
        try:
            import weasyprint  # noqa: F401

            pytest.skip("weasyprint native libs load; graceful-failure path not exercised")
        except OSError:
            pass
        except ImportError:
            pytest.skip("weasyprint not installed; native-lib path not exercised")
        with pytest.raises(RuntimeError, match=r"GTK3 Runtime|native libraries"):
            render_pdf("<html><body>x</body></html>", tmp_path / "out.pdf")


