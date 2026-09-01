"""Deterministic in-process SQLi target fixture for golden tests.

Endpoints
---------
- ``/sqli/error``   — injectable: a ``'`` in the value yields a MySQL error
  signature → error-based finding.
- ``/sqli/boolean`` — injectable: ``1=1`` vs ``1=2`` return different bodies
  (delta for boolean-blind) but never an error signature.
- ``/sqli/safe``    — negative control: fixed page, never evaluates input.
- ``/sqli/noisy``   — negative control: emits a random CSRF token + timestamp
  on every response but is NOT injectable (identical bodies for any input).

Run standalone::

    poetry run python tests/golden/sqli_target.py --port 18099
"""

from __future__ import annotations

import argparse
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


# Substrings emitted per endpoint; keep them OUT of the SQLi error signatures
# (:error route emits a real signature via the ;error marker).
TRUE_BODY = "<html><body><h1>Results</h1><p>5 rows returned.</p></body></html>"
FALSE_BODY = "<html><body><h1>Results</h1><p>No rows found.</p></body></html>"
NORMAL_BODY = "<html><body><h1>Results</h1><p>1 row returned.</p></body></html>"
SAFE_BODY = "<html><body><h1>Static page</h1><p>No dynamic SQL here.</p></body></html>"


def _noisy_body(value: str) -> str:
    # Random token + timestamp change every response, but the page is never
    # injectable: identical structure regardless of the injected value.
    token = uuid.uuid4().hex
    ts = int(time.time() * 1000)
    return (
        "<html><body><h1>Dashboard</h1>"
        f'<input type="hidden" name="csrf" value="{token}">'
        f"<p>session refresh at {ts}</p>"
        f"<p>Pinned value: {value}</p>"
        "</body></html>"
    )


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802 (http.server API)
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        value = (params.get("id") or [""])[0]

        if parsed.path == "/sqli/error":
            if "'" in value:
                # Emits a MySQL "you have an error in your SQL syntax" marker.
                self._send(200, "<html><body>You have an error in your SQL syntax; "
                                "check the manual near '1'' at line 1</body></html>")
            else:
                self._send(200, NORMAL_BODY)
        elif parsed.path == "/sqli/boolean":
            if "1=1" in value:
                self._send(200, TRUE_BODY)
            elif "1=2" in value:
                self._send(200, FALSE_BODY)
            else:
                self._send(200, NORMAL_BODY)
        elif parsed.path == "/sqli/safe":
            self._send(200, SAFE_BODY)
        elif parsed.path == "/sqli/noisy":
            self._send(200, _noisy_body(value))
        else:
            self._send(404, "not found")

    def log_message(self, *args):  # silence stderr noise
        pass

    def _send(self, status: int, text: str):
        data = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class SqliTargetServer:
    """Threaded SQLi fixture bound to 127.0.0.1 on an ephemeral port."""

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
    parser = argparse.ArgumentParser(description="Local SQLi golden target")
    parser.add_argument("--port", type=int, default=18099)
    args = parser.parse_args()

    httpd = ThreadingHTTPServer(("127.0.0.1", args.port), _Handler)
    print(f"SQLi fixture on http://127.0.0.1:{args.port}/sqli/error?id=<payload>", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    main()
