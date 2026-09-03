"""Report hygiene: redaction of session secrets at the export boundary, confidence
breakdown in aggregates, host grouping, and technique/confidence narrative hints."""
import asyncio

from pwnproxy.ai.llm.testing import FakeLLMClient
from pwnproxy.ai.reports.analyzer import dedup_findings, risk_aggregates
from pwnproxy.ai.reports.generator import GroupNarrative, ReportGenerator
from pwnproxy.ai.reports.redact import redact_request_data, redact_secrets
from pwnproxy.ai.reports.render import render_html, render_markdown

SESSION_COOKIE = "PHPSESSID=d1878681b66c88d09b4635443ac15174; security=high"


def _finding(url="http://host-a.local/vuln", confidence="inferred", **over):
    base = {
        "scanner": "sqli",
        "url": url,
        "method": "GET",
        "param_name": "q",
        "param_location": "query",
        "technique": "error-based",
        "severity": "high",
        "confidence": confidence,
        "payload": "' OR 1=1--",
        "evidence": "SQLSTATE syntax error",
        "timestamp": None,
        "extra": {},
        "request_data": {"request": "GET /vuln?q=x HTTP/1.1"},
    }
    base.update(over)
    return base


class TestRedactSecrets:
    def test_session_cookie_redacted(self):
        out = redact_secrets(f"cookie: {SESSION_COOKIE}")
        assert "d1878681b66c88d09b4635443ac15174" not in out
        assert "[redacted]" in out
        # non-secret cookie (security level) survives
        assert "security=high" in out

    def test_authorization_bearer_keeps_scheme(self):
        out = redact_secrets("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc")
        assert "eyJhbGciOiJIUzI1NiJ9.abc" not in out
        assert "Bearer [redacted]" in out

    def test_proxy_authorization_basic(self):
        out = redact_secrets("Proxy-Authorization: Basic dXNlcjpwYXNz")
        assert "dXNlcjpwYXNz" not in out
        assert "Basic [redacted]" in out

    def test_password_in_query_string(self):
        out = redact_secrets("url?password=supersecret&x=1&y=2")
        assert "supersecret" not in out
        assert "[redacted]" in out

    def test_csrf_token_not_redacted(self):
        out = redact_secrets("&csrf=abc123def&_token=xyz789")
        assert "abc123def" in out and "xyz789" in out

    def test_technical_evidence_intact(self):
        ev = 'SQLSTATE[HY000]: General error near "1" syntax error <img src=x onerror=alert(1)>'
        assert redact_secrets(ev) == ev

    def test_request_data_deep_copy_no_mutation(self):
        rd = {
            "method": "GET",
            "url": "http://x/vuln?password=hidden1",
            "headers": {"cookie": SESSION_COOKIE, "authorization": "Bearer tok123",
                        "user-agent": "UA/1.0"},
            "body": "password=plain&name=x",
        }
        out = redact_request_data(rd)
        assert "hidden1" not in out["url"]
        assert "d1878681b66c88d09b4635443ac15174" not in out["headers"]["cookie"]
        assert "tok123" not in out["headers"]["authorization"]
        assert "plain" not in out["body"]
        assert out["headers"]["user-agent"] == "UA/1.0"
        # original untouched
        assert rd["headers"]["cookie"] == SESSION_COOKIE
        assert rd["url"] == "http://x/vuln?password=hidden1"


class TestReportIntegrationRedaction:
    def test_generated_markdown_has_no_session_secret(self, tmp_path):
        findings = [
            _finding(url="http://host-a.local/xss_r/?name=x", confidence="inferred",
                     payload="<img src=x onerror=alert(1)>",
                     evidence="reflection of param",
                     request_data={"headers": {"cookie": SESSION_COOKIE},
                                   "url": "http://host-a.local/xss_r/?name=%3Cimg%3E"}),
        ]
        groups = dedup_findings(findings)
        for g in groups:
            g["facts"] = {
                "title": "Reflected XSS", "severity": "high", "vector": "reflection",
                "key_evidence": "reflection of param", "impact": "session theft risk",
                "remediation": "encode output",
            }
            g["flagged"] = False
        gen = ReportGenerator(FakeLLMClient(), session_name="test")
        # build context directly (avoids needing narrative/aggregate round-trips)
        aggregates = risk_aggregates(groups, raw_count=len(findings))
        narratives = [GroupNarrative(
            title="Reflected XSS", description="weakness", impact_paragraph="impact",
            remediation_steps=["encode"],
        )]
        context = gen._build_context(aggregates, groups, narratives, "exec", "technical")
        md = render_markdown(context)
        assert "d1878681b66c88d09b4635443ac15174" not in md
        assert "[redacted]" in md
        html = render_html(context, md)
        assert "d1878681b66c88d09b4635443ac15174" not in html

    def test_context_request_data_redacted(self):
        findings = [
            _finding(confidence="confirmed",
                     request_data={"headers": {"cookie": SESSION_COOKIE}}),
        ]
        groups = dedup_findings(findings)
        for g in groups:
            g["facts"] = {"title": "T", "severity": "high", "vector": "v",
                          "key_evidence": "e", "impact": "i", "remediation": "r"}
            g["flagged"] = False
        gen = ReportGenerator(FakeLLMClient(), session_name="test")
        aggregates = risk_aggregates(groups, raw_count=1)
        context = gen._build_context(aggregates, groups,
                                     [GroupNarrative(title="T", description="", impact_paragraph="",
                                                     remediation_steps=[])],
                                     "exec", "technical")
        assert "d1878681b66c88d09b4635443ac15174" not in context["sections"][0]["request_data_json"]


class TestRiskAggregatesConfidence:
    def test_breakdown_all_levels_plus_other(self):
        groups = [
            _finding(url="http://a.local/1", confidence="confirmed"),
            _finding(url="http://a.local/2", confidence="confirmed"),
            _finding(url="http://a.local/3", confidence="inferred"),
            _finding(url="http://a.local/4", confidence="tentative"),
            _finding(url="http://a.local/5", confidence="unknown-value"),
        ]
        agg = risk_aggregates(groups, raw_count=5)
        assert agg["by_confidence"]["confirmed"] == 2
        assert agg["by_confidence"]["inferred"] == 1
        assert agg["by_confidence"]["tentative"] == 1
        assert agg["by_confidence"]["other"] == 1
        assert agg["confirmed"] == 2  # backward compatible

    def test_host_breakdown_multi_host(self):
        groups = [
            _finding(url="http://a.local/1", confidence="confirmed"),
            _finding(url="http://a.local/2", confidence="inferred"),
            _finding(url="http://b.local/3", confidence="confirmed"),
        ]
        agg = risk_aggregates(groups, raw_count=3)
        assert set(agg["affected_hosts"]) == {"a.local", "b.local"}
        assert agg["by_host"]["a.local"]["groups"] == 2
        assert agg["by_host"]["b.local"]["groups"] == 1
        assert agg["by_host"]["a.local"]["by_confidence"]["confirmed"] == 1
        assert agg["by_host"]["a.local"]["by_confidence"]["inferred"] == 1

    def test_single_host_no_redundant_key(self):
        groups = [_finding(url="http://a.local/1", confidence="confirmed"),
                  _finding(url="http://a.local/2", confidence="tentative")]
        agg = risk_aggregates(groups, raw_count=2)
        assert len(agg["by_host"]) == 1


class TestNarrativeMetadataInjection:
    def test_metadata_block_contains_technique_confidence_severity(self):
        gen = ReportGenerator(FakeLLMClient(), session_name="test")
        group = _finding(url="http://a.local/1", confidence="inferred",
                         technique="error-based", severity="high")
        meta = gen._metadata_block(group)
        assert "error-based" in meta
        assert "inferred" in meta
        assert "high" in meta
        assert "authoritative" in meta

    def test_narrative_user_message_carries_metadata(self):
        from pwnproxy.ai.llm.models import LLMMessage, LLMRequest

        captured: list = []

        class CapturingFake(FakeLLMClient):
            async def generate(self, request, *a, **k):
                captured.append(request)
                return await super().generate(request)

        group = _finding(url="http://a.local/1", confidence="tentative",
                         technique="blind boolean", severity="medium")
        group["facts"] = {
            "title": "Blind injection", "severity": "medium", "vector": "boolean",
            "key_evidence": "e", "impact": "i", "remediation": "r",
        }

        async def run():
            async def _noop(done, total):
                return None

            gen = ReportGenerator(CapturingFake([]), session_name="test")
            # script a narrative-shaped response so schema validation passes
            payload = ('{"title":"Blind injection","description":"d","impact_paragraph":"i",'
                       '"remediation_steps":["fix"]}')
            gen._llm.push(payload)
            await gen._write_narratives([group], "technical", _noop)

        asyncio.run(run())
        assert captured, "narrative call should have been made"
        user_msgs = " ".join(m.content for m in captured[0].messages if m.role == "user")
        assert "blind boolean" in user_msgs
        assert "tentative" in user_msgs
        assert "authoritative" in user_msgs
