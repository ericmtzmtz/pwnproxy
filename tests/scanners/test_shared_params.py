from pwnproxy.scanners.common.params import InjectionPoint, extract


def test_module_can_import():
    assert InjectionPoint is not None
    assert callable(extract)


def test_dataclass_fields():
    p = InjectionPoint(
        name="q", value="hello", location="query",
        flow_id="f1", method="GET", url="http://test.com/",
        host="test.com", path="/",
        original_headers={}, original_body=None,
    )
    assert p.name == "q"
    assert p.location == "query"
    assert p.host == "test.com"
    assert p.original_headers == {}
