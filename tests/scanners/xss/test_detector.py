from unittest.mock import AsyncMock, MagicMock

import pytest

from pwnproxy.plugins.scanners.xss.detector import ReflectedDetector, StoredDetector
from pwnproxy.plugins.scanners.xss.models import XssFinding


class TestEncodingCheck:
    def test_encoded_pattern_detected(self):
        detector = ReflectedDetector.__new__(ReflectedDetector)
        assert detector._is_escaped("&lt;script&gt;alert(1)&lt;/script&gt;", "<script>alert(1)</script>") is True

    def test_no_encoding(self):
        detector = ReflectedDetector.__new__(ReflectedDetector)
        assert detector._is_escaped("<script>alert(1)</script>", "<script>alert(1)</script>") is False

    def test_escaped_with_raw_present_still_found(self):
        detector = ReflectedDetector.__new__(ReflectedDetector)
        assert detector._is_escaped("&lt;&gt; safe <script>alert(1)</script>", "<script>alert(1)</script>") is False

    def test_attr_breakout_encoded(self):
        detector = ReflectedDetector.__new__(ReflectedDetector)
        encoded = "&quot; onmouseover=alert(1) &quot;"
        assert detector._is_escaped(encoded, '" onmouseover=alert(1) "') is True


class TestStoredDetector:
    @pytest.mark.asyncio
    async def test_stored_match_creates_finding(self):
        canary_store = MagicMock()
        canary_store.scan_response = AsyncMock(return_value=[
            MagicMock(
                canary_value="pwnxss-abc123",
                source_url="http://source.com/page",
                param_name="comment",
                param_location="body",
                found_url="http://other.com/page",
            )
        ])
        detector = StoredDetector(canary_store)
        findings = await detector.check("response body pwnxss-abc123 here", "http://other.com/page")
        assert len(findings) == 1
        assert findings[0].xss_type == "stored"
        assert findings[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_no_match_no_finding(self):
        canary_store = MagicMock()
        canary_store.scan_response = AsyncMock(return_value=[])
        detector = StoredDetector(canary_store)
        findings = await detector.check("no canary here", "http://other.com/page")
        assert len(findings) == 0
