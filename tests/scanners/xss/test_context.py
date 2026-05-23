from pwnproxy.scanners.xss.context import ContextAnalyzer, ReflectionContext


def _analyze(body: str, canary: str = "pwnxss-probe") -> list[ReflectionContext]:
    return ContextAnalyzer().analyze(body, canary)


class TestHtmlBody:
    def test_between_tags(self):
        body = "<div>hello pwnxss-probe world</div>"
        ctxs = _analyze(body)
        assert ReflectionContext.HTML_BODY in ctxs

    def test_outside_tag_but_between_tags(self):
        body = "<p>text</p>pwnxss-probe<p>more</p>"
        ctxs = _analyze(body)
        assert ReflectionContext.HTML_BODY in ctxs


class TestHtmlAttr:
    def test_inside_attribute_value(self):
        body = '<input value="pwnxss-probe">'
        ctxs = _analyze(body)
        assert ReflectionContext.HTML_ATTR in ctxs

    def test_inside_single_quoted_attr(self):
        body = "<div class='pwnxss-probe'>"
        ctxs = _analyze(body)
        assert ReflectionContext.HTML_ATTR in ctxs


class TestJsString:
    def test_inside_script_block(self):
        body = "<script>var x = 'pwnxss-probe';</script>"
        ctxs = _analyze(body)
        assert ReflectionContext.JS_STRING in ctxs

    def test_inside_js_string_literal(self):
        body = "<script>const name = \"pwnxss-probe\";</script>"
        ctxs = _analyze(body)
        assert ReflectionContext.JS_STRING in ctxs


class TestUrlContext:
    def test_in_href_attribute(self):
        body = '<a href="pwnxss-probe">link</a>'
        ctxs = _analyze(body)
        assert ReflectionContext.URL in ctxs

    def test_in_src_attribute(self):
        body = '<script src="pwnxss-probe"></script>'
        ctxs = _analyze(body)
        assert ReflectionContext.URL in ctxs


class TestHtmlComment:
    def test_inside_comment(self):
        body = "<!-- comment pwnxss-probe -->"
        ctxs = _analyze(body)
        assert ReflectionContext.HTML_COMMENT in ctxs

    def test_comment_multiline(self):
        body = "<!--\n  pwnxss-probe\n-->"
        ctxs = _analyze(body)
        assert ReflectionContext.HTML_COMMENT in ctxs


class TestSvgNamespace:
    def test_xlink_href_image(self):
        body = '<image xlink:href="pwnxss-probe" height="200" width="200"/>'
        ctxs = _analyze(body)
        assert ReflectionContext.SVG_NAMESPACE in ctxs

    def test_xlink_href_use(self):
        body = '<use xlink:href="pwnxss-probe#lightning"/>'
        ctxs = _analyze(body)
        assert ReflectionContext.SVG_NAMESPACE in ctxs


class TestMultipleReflections:
    def test_two_positions(self):
        body = '<a href="pwnxss-probe">click</a><div>pwnxss-probe</div>'
        ctxs = _analyze(body)
        assert ReflectionContext.URL in ctxs
        assert ReflectionContext.HTML_BODY in ctxs
