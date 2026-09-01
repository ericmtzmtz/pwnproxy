"""Tests for DOM sink detection (static, no JS execution)."""
import pytest

from pwnproxy.plugins.scanners.xss.dom_sinks import (
    find_sinks,
    find_sink_snippet,
    find_param_location_sinks,
)


CANARY = "pwnxss-domtest"


def _html(script: str) -> str:
    return f"<html><body><script>{script}</script></body></html>"


class TestFindSinks:
    def test_document_write(self):
        script = f"var lang = 'x'; document.write('<option value=' + '{CANARY}' + '</option>');"
        sinks = find_sinks(_html(script), CANARY)
        assert any(s.name == "document.write" for s in sinks)

    def test_document_writeln(self):
        script = f"document.writeln('{CANARY}');"
        sinks = find_sinks(_html(script), CANARY)
        assert any(s.name == "document.write" for s in sinks)

    def test_inner_html(self):
        script = f"el.innerHTML = '{CANARY}';"
        sinks = find_sinks(_html(script), CANARY)
        assert any(s.name == "innerHTML" for s in sinks)

    def test_inner_html_concatenation(self):
        script = f"el.innerHTML = '<div>' + '{CANARY}' + '</div>';"
        sinks = find_sinks(_html(script), CANARY)
        assert any(s.name == "innerHTML" for s in sinks)

    def test_location_href(self):
        script = f"location.href = '{CANARY}';"
        sinks = find_sinks(_html(script), CANARY)
        assert any(s.name == "location.href" for s in sinks)

    def test_eval(self):
        script = f"eval('{CANARY}');"
        sinks = find_sinks(_html(script), CANARY)
        assert any(s.name == "eval" for s in sinks)

    def test_set_timeout(self):
        script = f"setTimeout('{CANARY}', 100);"
        sinks = find_sinks(_html(script), CANARY)
        assert any(s.name == "setTimeout" for s in sinks)

    def test_window_open(self):
        script = f"window.open('{CANARY}');"
        sinks = find_sinks(_html(script), CANARY)
        assert any(s.name == "window.open" for s in sinks)

    def test_canary_in_script_but_not_in_sink(self):
        script = f"var x = '{CANARY}'; console.log(x); var y = 1 + 2;"
        assert find_sinks(_html(script), CANARY) == []

    def test_canary_in_html_but_not_in_script(self):
        html = f"<html><body><div>{CANARY}</div><script>var a=1;</script></body></html>"
        assert find_sinks(html, CANARY) == []

    def test_canary_escaped_in_regex(self):
        # canary with regex metachars must be matched literally
        tricky = "a.b+c"
        script = f"document.write('{tricky}');"
        sinks = find_sinks(_html(script), tricky)
        assert any(s.name == "document.write" for s in sinks)

    def test_snippet_found(self):
        script = f"document.write('{CANARY}');"
        snippet = find_sink_snippet(_html(script), CANARY, find_sinks(_html(script), CANARY)[0])
        assert CANARY in snippet


class TestParamLocationSinks:
    def _html(self, script: str) -> str:
        return f"<html><body><script>{script}</script></body></html>"

    def test_indexof_location_read_into_document_write(self):
        # DVWA xss_d style — the server does NOT reflect the value.
        script = (
            "if (document.location.href.indexOf('default=') >= 0) {"
            "var lang = document.location.href.substring("
            "document.location.href.indexOf('default=')+8);"
            "document.write(\"<option value='\" + lang + \"'>\" + lang + \"</option>\");}"
        )
        sinks = find_param_location_sinks(self._html(script), "default")
        assert any(s.name == "document.write" for s in sinks)

    def test_urlsearchparams_get_into_innerhtml(self):
        script = (
            "var q = new URLSearchParams(location.search).get('q');"
            "document.getElementById('out').innerHTML = q;"
        )
        sinks = find_param_location_sinks(self._html(script), "q")
        assert any(s.name == "innerHTML" for s in sinks)

    def test_split_read_into_document_write(self):
        script = (
            "var lang = location.href.split('default=')[1];"
            "document.write(lang);"
        )
        sinks = find_param_location_sinks(self._html(script), "default")
        assert any(s.name == "document.write" for s in sinks)

    def test_param_not_read_no_sinks(self):
        script = "var x = 'other'; document.write(x);"
        assert find_param_location_sinks(self._html(script), "default") == []

    def test_read_but_no_sink_in_block(self):
        script = "var lang = location.href.indexOf('default=');"
        assert find_param_location_sinks(self._html(script), "default") == []

    def test_sink_but_param_not_from_location(self):
        script = "var lang = someData['default']; document.write(lang);"
        assert find_param_location_sinks(self._html(script), "default") == []
