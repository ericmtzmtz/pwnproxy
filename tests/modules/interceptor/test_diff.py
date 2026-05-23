import pytest

from pwnproxy.modules.interceptor.diff import (
    compute_body_diff,
    compute_headers_diff,
    compute_full_diff,
    MAX_DIFF_SIZE,
)
from pwnproxy.modules.interceptor.controller import FlowSnapshot
from pwnproxy.core.models import Flow


class TestComputeBodyDiff:

    def test_no_changes(self):
        result = compute_body_diff("hello\nworld", "hello\nworld")
        assert result == ["No changes"]

    def test_added_line(self):
        result = compute_body_diff("hello", "hello\nworld")
        assert any(line.startswith("+") for line in result)

    def test_removed_line(self):
        result = compute_body_diff("hello\nworld", "hello")
        assert any(line.startswith("-") for line in result)

    def test_large_body_truncated(self):
        big = "x" * (MAX_DIFF_SIZE + 1)
        result = compute_body_diff(big, big + "extra")
        assert result == ["Body too large for diff"]

    def test_empty_strings(self):
        result = compute_body_diff("", "")
        assert result == ["No changes"]


class TestComputeHeadersDiff:

    def test_no_changes(self):
        orig = {"Content-Type": "text/html"}
        ed = {"Content-Type": "text/html"}
        result = compute_headers_diff(orig, ed)
        assert result == ["No changes"]

    def test_header_added(self):
        orig = {"Content-Type": "text/html"}
        ed = {"Content-Type": "text/html", "X-Custom": "val"}
        result = compute_headers_diff(orig, ed)
        assert any("X-Custom" in line for line in result)

    def test_header_removed(self):
        orig = {"Content-Type": "text/html", "X-Custom": "val"}
        ed = {"Content-Type": "text/html"}
        result = compute_headers_diff(orig, ed)
        assert any("X-Custom" in line for line in result)

    def test_header_value_changed(self):
        orig = {"Content-Type": "text/html"}
        ed = {"Content-Type": "application/json"}
        result = compute_headers_diff(orig, ed)
        assert any("application/json" in line for line in result)

    def test_none_headers(self):
        result = compute_headers_diff(None, None)
        assert result == ["No changes"]


class TestComputeFullDiff:

    def _snapshot(self, **overrides) -> FlowSnapshot:
        flow = Flow(
            id="t",
            method="GET",
            url="http://x.com/",
            request_headers={"A": "1"},
            request_body=b"req body",
            status_code=200,
            response_headers={"B": "2"},
            response_body=b"res body",
            **{k: v for k, v in overrides.items() if hasattr(Flow, k)},
        )
        return FlowSnapshot.from_flow(flow)

    def test_full_diff_all_sections(self):
        orig = self._snapshot()
        edited_flow = Flow(
            id="t", method="POST", url="http://y.com/",
            request_headers={"A": "2"}, request_body=b"req edited",
            status_code=201, response_headers={"B": "3"},
            response_body=b"res edited",
        )
        edited = FlowSnapshot.from_flow(edited_flow)
        result = compute_full_diff(orig, edited)

        assert "request_body" in result
        assert "request_headers" in result
        assert "response_body" in result
        assert "response_headers" in result

        assert any(line != "No changes" for section in result.values() for line in section)

    def test_full_diff_no_changes(self):
        orig = self._snapshot()
        same = self._snapshot()
        result = compute_full_diff(orig, same)

        for section in result.values():
            assert section == ["No changes"]
