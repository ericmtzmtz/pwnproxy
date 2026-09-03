"""WAF/rate-limit guards on the error-based status differential."""
from unittest.mock import MagicMock

import pytest

from pwnproxy.plugins.scanners.sqli.payloads import CONTROL_PAYLOADS, get_error_payloads
from pwnproxy.plugins.scanners.sqli.signatures import ERROR_SIGNATURES
from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.shared.scan.stages.sqli_stages import ErrorBasedStage

WAF_BODY = "<html>The request was blocked by Mod_Security</html>"
NORMAL_500 = "<html>application error page</html>"


class GuardReplayer:
    """Replayer that decides status by payload: SQL-payload rule, control rule,
    rate-limit rule, and optional WAF headers on 5xx responses."""

    def __init__(self, sql_status=500, control_status=200, rate_status=None,
                 waf_headers=False, clean_status=200):
        self._sql_status = sql_status
        self._control_status = control_status
        self._rate_status = rate_status
        self._waf_headers = waf_headers
        self._clean_status = clean_status
        self.payload_calls = 0

    def _mk(self, status, text):
        resp = MagicMock()
        resp.status_code = status
        resp.text = text
        headers = {}
        if self._waf_headers:
            headers = {"server": "cloudflare", "cf-ray": "abc123"}
        resp.headers = headers
        return resp

    async def send_clean(self, point, timeout=10.0):
        return self._mk(self._clean_status, "<html>normal</html>")

    async def replay(self, point, payload, timeout=3.0, evasion_level="none"):
        self.payload_calls += 1
        sql_payloads = {p.value for p in get_error_payloads()}
        control_payloads = {p.value for p in CONTROL_PAYLOADS}
        if self._rate_status is not None and payload in sql_payloads:
            return self._mk(self._rate_status, "<html>rate limited</html>")
        if payload in sql_payloads:
            body = WAF_BODY if self._waf_headers else NORMAL_500
            return self._mk(self._sql_status, body)
        if payload in control_payloads:
            return self._mk(self._control_status, "<html>control ok</html>")
        return self._mk(200, "<html>ok</html>")

    def build_payload_request(self, point, payload, evasion_level="none"):
        return MagicMock()


def _point(name="title", location="query") -> InjectionPoint:
    return InjectionPoint(
        name=name, value="test", location=location,
        flow_id="f1", method="GET", url="http://target.com/sqli_1.php?title=test&action=search",
        host="target.com", path="/sqli_1.php",
        original_headers={"Host": "target.com"}, original_body=None,
    )


def _flow():
    from pwnproxy.shared.models import Flow
    return Flow(id="f1", method="GET", url="http://target.com/sqli_1.php?title=test&action=search",
                request_headers={"Host": "target.com"})


@pytest.mark.asyncio
async def test_waf_block_page_on_5xx_no_finding():
    replayer = GuardReplayer(sql_status=500, waf_headers=True)
    stage = ErrorBasedStage(replayer, ERROR_SIGNATURES, get_error_payloads())
    result = await stage.execute(_flow(), [_point()])
    assert result.findings == []


@pytest.mark.asyncio
async def test_control_also_5xx_no_finding():
    """Non-SQL control induces 5xx too -> status change not attributable to SQL."""
    replayer = GuardReplayer(sql_status=500, control_status=500)
    stage = ErrorBasedStage(replayer, ERROR_SIGNATURES, get_error_payloads())
    result = await stage.execute(_flow(), [_point()])
    assert result.findings == []


@pytest.mark.asyncio
async def test_rate_limit_503_not_counted_as_trigger():
    """503 on SQL payloads is excluded from the differential triggers -> no finding."""
    replayer = GuardReplayer(rate_status=503)
    stage = ErrorBasedStage(replayer, ERROR_SIGNATURES, get_error_payloads())
    result = await stage.execute(_flow(), [_point()])
    assert result.findings == []


@pytest.mark.asyncio
async def test_mostly_rate_limited_aborts_point():
    """Half or more of the payloads 503 -> abort the point entirely."""
    replayer = GuardReplayer(rate_status=503)
    stage = ErrorBasedStage(replayer, ERROR_SIGNATURES, get_error_payloads())
    result = await stage.execute(_flow(), [_point()])
    assert result.findings == []


@pytest.mark.asyncio
async def test_bad_gateway_502_not_counted_as_trigger():
    """A dead/half-open proxy answering 502 for every SQL payload must NOT be
    treated as an error-payload induced 5xx (proxy failed, not the query)."""
    replayer = GuardReplayer(rate_status=502)
    stage = ErrorBasedStage(replayer, ERROR_SIGNATURES, get_error_payloads())
    result = await stage.execute(_flow(), [_point()])
    assert result.findings == []


@pytest.mark.asyncio
async def test_mixed_502_and_sql_500_only_counts_real_triggers():
    """Some 502s among genuine 500s: only the true 500s count toward the ladder.
    With just one real 500 the finding is tentative; the 502s don't push it up."""
    class MixedReplayer(GuardReplayer):
        def __init__(self):
            super().__init__(sql_status=500, control_status=200)
            self._calls = 0

        async def replay(self, point, payload, timeout=3.0, evasion_level="none"):
            self._calls += 1
            sql_payloads = {p.value for p in get_error_payloads()}
            if payload in sql_payloads:
                # every third SQL payload is a 502 (intermittent proxy failure)
                if self._calls % 3 == 0:
                    return self._mk(502, "<html>bad gateway</html>")
            return await super().replay(point, payload, timeout=timeout, evasion_level=evasion_level)

    replayer = MixedReplayer()
    stage = ErrorBasedStage(replayer, ERROR_SIGNATURES, get_error_payloads())
    result = await stage.execute(_flow(), [_point()])
    assert len(result.findings) == 1
    assert result.findings[0].confidence == "tentative"
    assert result.findings[0].extra["partial_triggers"] is True


@pytest.mark.asyncio
async def test_clean_5xx_over_control_emits_tentative():
    """Real muted-SQL signal: SQL 5xx, control 200, no WAF -> tentative/medium."""
    replayer = GuardReplayer(sql_status=500, control_status=200)
    stage = ErrorBasedStage(replayer, ERROR_SIGNATURES, get_error_payloads())
    result = await stage.execute(_flow(), [_point()])
    assert len(result.findings) == 1
    assert result.findings[0].confidence == "tentative"
    assert result.findings[0].extra["control_passed"] is True
