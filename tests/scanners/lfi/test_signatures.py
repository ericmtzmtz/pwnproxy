from pwnproxy.services.scanners.lfi.signatures import detect_os


class TestDetectOs:
    def test_unix_passwd(self):
        body = "root:x:0:0:root:/root:/bin/bash"
        os_type, evidence = detect_os(body)
        assert os_type == "unix"
        assert evidence == "root:x:0:0:"

    def test_unix_daemon(self):
        body = "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
        os_type, evidence = detect_os(body)
        assert os_type == "unix"
        assert evidence == "daemon:x:1:1:"

    def test_windows_extensions(self):
        body = "[extensions]\r\nmru=1\r\n"
        os_type, evidence = detect_os(body)
        assert os_type == "windows"

    def test_windows_fonts(self):
        body = "[fonts]"
        os_type, evidence = detect_os(body)
        assert os_type == "windows"

    def test_php_base64(self):
        body = "PD9waHAgZWNobyAiSGVsbG8iOyA/Pg=="
        os_type, evidence = detect_os(body)
        assert os_type == "php"

    def test_php_base64_multiline(self):
        body = "line1\nPD9waHAgZWNobyAiSGVsbG8iOyA/Pg==\nline3"
        os_type, evidence = detect_os(body)
        assert os_type == "php"

    def test_no_match_returns_none(self):
        body = "<html><body>Hello world</body></html>"
        os_type, evidence = detect_os(body)
        assert os_type is None
        assert evidence is None
