"""Deterministic in-process XSS target fixture for golden tests.

Serves ``GET /reflect?name=<input>`` which reflects the raw query value
unescaped into the HTML body — the classic reflected-XSS signal that
``ReflectedStage`` detects. Also serves a ``/safe`` endpoint that HTML-escapes
the input (negative control: the scanner must NOT flag it).

Run standalone::

    poetry run python tests/golden/xss_target.py --port 18098
"""

from __future__ import annotations

import argparse
import html as html_mod
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802 (http.server API)
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        value = (params.get("name") or [""])[0]
        if parsed.path == "/reflect":
            # Vulnerable: raw reflection, no escaping.
            body = f"<html><body>Hello, {value}</body></html>"
        elif parsed.path == "/safe":
            # Negative control: properly escaped.
            body = f"<html><body>Hello, {html_mod.escape(value)}</body></html>"
        elif parsed.path == "/attr":
            # Vulnerable: value inside a double-quoted attribute, no escaping.
            body = f'<html><body><input type="text" name="fn" value="{value}"></body></html>'
        elif parsed.path == "/attr-safe":
            # Negative control: escaped attribute value → no breakout.
            body = f'<html><body><input type="text" name="fn" value="{html_mod.escape(value, quote=True)}"></body></html>'
        elif parsed.path == "/js":
            # Vulnerable: value inside a JS string literal.
            body = f"<html><body><script>var name = \"{value}\";</script></body></html>"
        elif parsed.path == "/comment":
            # Vulnerable: value inside an HTML comment.
            body = f"<html><body><!-- user note: {value} --></body></html>"
        else:
            self._send(404, "not found")
            return
        self._send(200, body)

    def log_message(self, *args):  # silence stderr noise
        pass

    def _send(self, status: int, text: str):
        data = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class XssTargetServer:
    """Threaded XSS fixture bound to 127.0.0.1 on an ephemeral port."""

    def __init__(self):
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._httpd.server_address[1]}"

    def start(self):
        self._thread.start()

    def stop(self):
        self._httpd.shutdown()
        self._httpd.server_close()


def main():
    parser = argparse.ArgumentParser(description="Local XSS golden target")
    parser.add_argument("--port", type=int, default=18098)
    args = parser.parse_args()

    httpd = ThreadingHTTPServer(("127.0.0.1", args.port), _Handler)
    print(f"XSS fixture on http://127.0.0.1:{args.port}/reflect?name=<payload>", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    main()
