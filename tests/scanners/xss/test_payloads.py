from pwnproxy.services.scanners.xss.payloads import (
    HTML_BODY_PAYLOADS,
    ATTR_BREAKOUT_PAYLOADS,
    JS_STRING_PAYLOADS,
    URL_CONTEXT_PAYLOADS,
    COMMENT_BREAKOUT_PAYLOADS,
    SVG_NAMESPACE_PAYLOADS,
    get_payloads_for_context,
)


class TestPayloadCounts:
    def test_html_body_has_new_payloads(self):
        descs = {p.description for p in HTML_BODY_PAYLOADS}
        assert "WAF evasion via details ontoggle" in descs
        assert "Filter evasion via nested script tags" in descs
        assert "HTML5 video source onerror" in descs
        assert "Cookie exfiltration via fetch" in descs
        assert "Stealth console.log (stored XSS)" in descs
        assert len(HTML_BODY_PAYLOADS) == 11

    def test_attr_has_polyglot(self):
        descs = {p.description for p in ATTR_BREAKOUT_PAYLOADS}
        assert "Polyglot across contexts" in descs
        assert len(ATTR_BREAKOUT_PAYLOADS) == 5

    def test_js_has_template_literal(self):
        descs = {p.description for p in JS_STRING_PAYLOADS}
        assert "Template-literal JS string breakout" in descs
        assert "Cookie steal via fetch breakout" in descs
        assert len(JS_STRING_PAYLOADS) == 6

    def test_url_has_base64(self):
        descs = {p.description for p in URL_CONTEXT_PAYLOADS}
        assert "Javascript confirm dialog" in descs
        assert "Data URI base64-encoded script" in descs
        assert len(URL_CONTEXT_PAYLOADS) == 4

    def test_comment_has_svg(self):
        descs = {p.description for p in COMMENT_BREAKOUT_PAYLOADS}
        assert "HTML comment close + svg onload" in descs
        assert len(COMMENT_BREAKOUT_PAYLOADS) == 3

    def test_svg_namespace_payloads(self):
        assert len(SVG_NAMESPACE_PAYLOADS) == 2


class TestGetPayloadsForContext:
    def test_returns_empty_for_unknown(self):
        assert get_payloads_for_context("unknown") == []

    def test_returns_svg_payloads(self):
        payloads = get_payloads_for_context("svg_namespace")
        assert len(payloads) == 2
        assert all(p.context == "svg_namespace" for p in payloads)
