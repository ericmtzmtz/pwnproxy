"""Deterministic in-process command-injection target fixture.

Endpoints
---------
- ``/cmd``  — injectable: values containing shell metacharacters return
  ``id``-style output (``uid=33(www-data) ...``) which matches the command
  output signatures → finding.
- ``/safe`` — negative control: static page, never reflects command output.
- ``/pdf``  — negative control: answers a PDF document whatever the payload is
  (the false positive from the live run: a PDF decoded as text has ``endobj``,
  ``stream`` and other bare tokens on their own lines).
- ``/preexisting`` — negative control: a text page that *already* prints
  ``uid=0(root) gid=0(root) `` without any payload, so the signature is page
  text and not command output.

Run standalone::

    poetry run python tests/golden/command_injection_target.py --port 18100
"""

from __future__ import annotations

import argparse
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

SAFE_BODY = "<html><body><h1>Static page</h1><p>Nothing dynamic here.</p></body></html>"
CMD_OUTPUT = "uid=0(root) gid=0(root) groups=0(root)\n"
PREEXISTING_OUTPUT = "uid=0(root) gid=0(root) groups=0(root)\n"
# Minimal PDF: ASCII only, with the isolated lowercase keywords that the old
# line-based `whoami` signature mistook for a username.
PDF_BODY = (
    b"%PDF-1.4\n"
    b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] >>\nendobj\n"
    b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources 6 0 R >>\nendobj\n"
    b"6 0 obj\n<< /ProcSet [/PDF /Text] /Font << /F1 7 0 R >> >>\nendobj\n"
    b"stream\nendstream\n"
    b"trailer\n<< /Root 1 0 R >>\nstartxref\n0\n%%EOF\n"
)

_METACHARS = (";", "|", "`", "$(", "&")


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.server.hits += 1  # type: ignore[attr-defined]
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        value = (params.get("cmd") or [""])[0]

        if parsed.path == "/pdf":
            data, content_type = PDF_BODY, "application/pdf"
        elif parsed.path == "/preexisting":
            data, content_type = PREEXISTING_OUTPUT.encode("utf-8"), "text/plain"
        elif parsed.path == "/cmd" and any(m in value for m in _METACHARS):
            data, content_type = CMD_OUTPUT.encode("utf-8"), "text/plain"
        else:
            data, content_type = SAFE_BODY.encode("utf-8"), "text/plain"

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):  # silence
        pass


class CommandInjectionTargetServer:
    """Threaded command-injection fixture bound to 127.0.0.1 on an ephemeral port."""

    def __init__(self):
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._httpd.hits = 0
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._httpd.server_address[1]}"

    @property
    def request_count(self) -> int:
        """Number of HTTP requests the fixture has answered so far."""
        return self._httpd.hits

    @property
    def pdf_body(self) -> bytes:
        """The PDF document served by ``/pdf``."""
        return PDF_BODY

    def start(self):
        self._thread.start()

    def stop(self):
        self._httpd.shutdown()
        self._httpd.server_close()


def main():
    parser = argparse.ArgumentParser(description="Local command-injection golden target")
    parser.add_argument("--port", type=int, default=18100)
    args = parser.parse_args()
    httpd = ThreadingHTTPServer(("127.0.0.1", args.port), _Handler)
    httpd.hits = 0
    print(f"Command-injection fixture on http://127.0.0.1:{args.port}/cmd?cmd=<payload>", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    main()
