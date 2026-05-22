from pwnproxy.core.db import truncate_body

def test_truncate_body():
    body, trunc = truncate_body(b"hello", max_size=10)
    assert body == b"hello"
    assert trunc is False
    
    body, trunc = truncate_body(b"hello world", max_size=5)
    assert body == b"hello"
    assert trunc is True
    
    body, trunc = truncate_body(None)
    assert body is None
    assert trunc is False
