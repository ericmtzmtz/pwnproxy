import argparse
import json
import tempfile
from pathlib import Path

from pwnproxy.services.proxy.proxy_worker import ProxyWorker


def _args(db_path: str) -> argparse.Namespace:
    ns = argparse.Namespace()
    ns.scope_enabled = False
    ns.scope_json = None
    ns.scope_pattern = []
    ns.db_path = db_path
    ns.listen_host = "127.0.0.1"
    ns.listen_port = 0
    ns.ssl_insecure = True
    ns.upstream = None
    ns.capture_enabled = True
    ns.confdir = "~/.mitmproxy"
    return ns


class TestWorkerScopeReload:
    def test_reload_scope_updates_live_filter(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            db_path = str(Path(tmp) / "traffic.db")
            worker = ProxyWorker(_args(db_path))

            # No scope.json yet -> reload fails, filter stays permissive.
            assert worker.reload_scope() is False
            assert worker._flow_filter.allow("http://anything.com/x")

            # Write scope.json with in_scope a.example.com -> reload applies.
            scope_file = Path(tmp) / "scope.json"
            scope_file.write_text(json.dumps(
                {"enabled": True, "in_scope": ["a.example.com"], "out_of_scope": []}
            ))
            assert worker.reload_scope() is True
            assert worker._flow_filter.allow("http://a.example.com/x")
            assert not worker._flow_filter.allow("http://b.example.com/x")

            # Write a new scope.json b.example.com -> live filter switches without rebuild.
            scope_file.write_text(json.dumps(
                {"enabled": True, "in_scope": ["b.example.com"], "out_of_scope": []}
            ))
            assert worker.reload_scope() is True
            assert not worker._flow_filter.allow("http://a.example.com/x")
            assert worker._flow_filter.allow("http://b.example.com/x")

    def test_initial_scope_json_builds_filter(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            ns = _args(str(Path(tmp) / "traffic.db"))
            ns.scope_json = json.dumps(
                {"enabled": True, "in_scope": ["localhost:4280"], "out_of_scope": []}
            )
            worker = ProxyWorker(ns)
            assert worker._flow_filter.allow("http://localhost:4280/sqli")
            assert not worker._flow_filter.allow("https://gj.mmstat.com/collect")
