"""Tests for XML body injection-point extraction (used by XXE scanner)."""

import uuid

from pwnproxy.shared.models import Flow
from pwnproxy.shared.scan.params import extract


def _xml_flow(content_type="text/xml"):
    return Flow(
        id=str(uuid.uuid4()),
        method="POST",
        url="http://example.com/xxe",
        request_headers={"Content-Type": content_type, "host": "example.com"},
        request_body=b"<reset><login>bee</login><secret>x</secret></reset>",
        status_code=200,
        response_headers={},
        response_body=b"ok",
        duration_ms=1,
        tls=False,
    )


def test_xml_content_type_produces_body_point():
    points = extract(_xml_flow())
    assert len(points) == 1
    p = points[0]
    assert p.location == "body"
    assert p.name == "xml_body"
    assert p.original_body == "<reset><login>bee</login><secret>x</secret></reset>"


def test_xml_body_without_content_type_still_extracted():
    flow = _xml_flow(content_type="")
    points = extract(flow)
    assert any(p.name == "xml_body" for p in points)


def test_form_body_still_extracts_named_params():
    flow = _xml_flow(content_type="application/x-www-form-urlencoded")
    flow.request_body = b"title=test&action=search"
    points = extract(flow)
    assert len(points) == 2
    assert {p.name for p in points} == {"title", "action"}
