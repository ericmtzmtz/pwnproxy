from pwnproxy.intruder.parser import parse_markers


class TestParseMarkers:
    def test_no_markers(self):
        template, markers = parse_markers("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        assert template == "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        assert markers == []

    def test_single_marker(self):
        template, markers = parse_markers("user=§admin§")
        assert template == "user={0}"
        assert markers == [(0, "admin")]

    def test_multiple_markers(self):
        template, markers = parse_markers("user=§admin§&pass=§1234§")
        assert template == "user={0}&pass={1}"
        assert markers == [(0, "admin"), (1, "1234")]

    def test_markers_in_headers(self):
        raw = "GET /api HTTP/1.1\r\nHost: §example.com§\r\n\r\n"
        template, markers = parse_markers(raw)
        assert "Host:" in template
        assert markers == [(0, "example.com")]

    def test_empty_marker(self):
        template, markers = parse_markers("§§")
        assert template == "{0}"
        assert markers == [(0, "")]
