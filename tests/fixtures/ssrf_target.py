"""Local vulnerable SSRF target fixture for E2E scanner validation.

Exposes ``GET /fetch?url=<target>``: performs a server-side request to
``<target>`` (classic in-scope-only SSRF) and returns the upstream status
and a body excerpt, or a 200 with an error message if the upstream
connection fails (e.g. connection refused). Always responds 200 so the
SSRF scanner's SsrfSimpleStage (status < 400 heuristic) can flag it.

Run standalone::

    poetry run python tests/fixtures/ssrf_target.py --port 18099

Manual validation against PortSwigger Web Security Academy SSRF labs
(the "Server-side request forgery (simple)" lab family):

1. Start the lab in your browser (https://portswigger.net/web-security/ssrf).
2. Open the lab and note the stock check endpoint, e.g.
   ``/product/stock?productId=1&storeId=1``.
3. Extract your lab session cookie from the browser (PHPSESSID or similar).
4. Run the scanner pointing at the stock check with a URL probe:

       poetry run pwnproxy scan url "https://<LAB-ID>.web-security-academy.net/product/stock?productId=1&storeId=1" \
           -s ssrf \
           --cookie "<LAB-SESSION-COOKIE>" \
           --data "productId=1&storeId=1" \
           --method POST \
           --content-type "application/x-www-form-urlencoded"

   The stock check fetches ``storeId`` server-side; the scanner's probe URL
   replaces it and the lab fetches it, producing the SSRF signal.

Note: labs rotate instance URLs and require an interactive browser
session, so they are NOT automated in CI — this local fixture is the
deterministic, offline validation path.
"""

from __future__ import annotations

import argparse
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

_UPSTREAM_TIMEOUT = 3.0
_EXCERPT_LEN = 500


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802 (http.server API)
        parsed = urlparse(self.path)
        if parsed.path != "/fetch":
            self._send(404, "not found")
            return
        params = parse_qs(parsed.query)
        target = (params.get("url") or [""])[0]
        if not target:
            self._send(200, "missing url param")
            return
        try:
            with urllib.request.urlopen(target, timeout=_UPSTREAM_TIMEOUT) as up:
                data = up.read(_EXCERPT_LEN)
                body = f"UPSTREAM_STATUS={up.status}\n{data.decode('utf-8', 'replace')}"
                self._send(200, body)
        except Exception as e:  # noqa: BLE001 — any upstream failure is a valid probe result
            # Always 200: connection-refused on the probe URL is the SSRF
            # detection signal, not a fixture error.
            self._send(200, f"UPSTREAM_ERROR={type(e).__name__}: {e}")

    def log_message(self, *args):  # silence stderr noise
        pass

    def _send(self, status: int, text: str):
        data = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class SsrfTargetServer:
    """Threaded SSRF fixture bound to 127.0.0.1 on an ephemeral port."""

    def __init__(self):
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        self._thread.start()

    def stop(self):
        self._httpd.shutdown()
        self._httpd.server_close()


def main():
    parser = argparse.ArgumentParser(description="Local SSRF validation target")
    parser.add_argument("--port", type=int, default=18099)
    args = parser.parse_args()

    httpd = ThreadingHTTPServer(("127.0.0.1", args.port), _Handler)
    print(f"SSRF fixture on http://127.0.0.1:{args.port}/fetch?url=<target>", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    main()
