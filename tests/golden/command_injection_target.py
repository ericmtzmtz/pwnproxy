"""Deterministic in-process command-injection target fixture.

Endpoints
---------
- ``/cmd``  — injectable: values containing shell metacharacters return
  ``id``-style output (``uid=33(www-data) ...``) which matches the command
  output signatures → finding.
- ``/safe`` — negative control: static page, never reflects command output.

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

_METACHARS = (";", "|", "`", "$(", "&")


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        value = (params.get("cmd") or [""])[0]

        body = CMD_OUTPUT if parsed.path == "/cmd" and any(m in value for m in _METACHARS) else SAFE_BODY

        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):  # silence
        pass


class CommandInjectionTargetServer:
    """Threaded command-injection fixture bound to 127.0.0.1 on an ephemeral port."""

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
    parser = argparse.ArgumentParser(description="Local command-injection golden target")
    parser.add_argument("--port", type=int, default=18100)
    args = parser.parse_args()
    httpd = ThreadingHTTPServer(("127.0.0.1", args.port), _Handler)
    print(f"Command-injection fixture on http://127.0.0.1:{args.port}/cmd?cmd=<payload>", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    main()
