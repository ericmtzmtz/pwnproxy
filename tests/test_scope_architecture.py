import json
import logging
import sys
from pathlib import Path

import pytest

from pwnproxy.services.session.manager import ScopeConfig
from pwnproxy.shared.hooks import HookBus


class TestScopeConfigSanitization:
    def test_to_dict_no_dead_fields(self):
        cfg = ScopeConfig()
        result = cfg.to_dict()
        assert "include_subdomains" not in result
        assert "ports" not in result
        assert set(result.keys()) == {"in_scope", "out_of_scope", "enabled"}

    def test_init_with_dead_fields_ignored(self):
        data = {"include_subdomains": True, "ports": [80], "in_scope": ["example.com"]}
        cfg = ScopeConfig(data)
        result = cfg.to_dict()
        assert "include_subdomains" not in result
        assert "ports" not in result
        assert result["in_scope"] == ["example.com"]

    def test_warning_on_enabled_empty_in_scope(self, caplog):
        caplog.set_level(logging.WARNING)
        ScopeConfig({"enabled": True, "in_scope": []})
        warnings = [rec.message for rec in caplog.records if rec.levelno == logging.WARNING]
        assert any("ScopeConfig enabled with empty in_scope list" in w for w in warnings)

    def test_is_in_scope_accepts_full_url(self):
        """URL with query string: host-based matching works."""
        cfg = ScopeConfig({"enabled": True, "in_scope": ["*.example.com"], "out_of_scope": []})
        assert cfg.is_in_scope("http://example.com/page?foo=bar") is True

    def test_is_in_scope_without_query_matches_host(self):
        """Host matching ignores path/query differences."""
        cfg = ScopeConfig({"enabled": True, "in_scope": ["*.example.com"], "out_of_scope": ["*.example.com"]})
        assert cfg.is_in_scope("http://example.com/admin?x=1") is False

    def test_is_in_scope_host_no_match(self):
        """Different host is not matched."""
        cfg = ScopeConfig({"enabled": True, "in_scope": ["*.example.com"], "out_of_scope": []})
        assert cfg.is_in_scope("http://evil.com/admin?x=1") is False


# Scope filter tests moved to FlowFilter implementation. HookBus no longer filters.


class TestProxyWorkerScope:
    @pytest.mark.asyncio
    async def test_reload_scope(self, tmp_path):
        from pwnproxy.services.proxy.proxy_worker import ProxyWorker
        import argparse
        scope_file = tmp_path / "scope.json"
        scope_file.write_text(json.dumps({"in_scope": [], "out_of_scope": [], "enabled": False}))
        args = argparse.Namespace(
            scope_enabled=False, scope_pattern=[], scope_json=None,
            listen_host="127.0.0.1", listen_port=8080,
            ssl_insecure=True, upstream=None,
            capture_enabled=True, db_path=str(tmp_path / "traffic.db"),
            confdir="~/.mitmproxy",
        )
        worker = ProxyWorker(args)
        assert worker._scope_config is None or worker._scope_config.enabled is False

        new_cfg = {"enabled": True, "in_scope": ["*.example.com"], "out_of_scope": ["*.admin.com"]}
        scope_file.write_text(json.dumps(new_cfg))
        result = worker.reload_scope()
        assert result is True
        assert worker._scope_config.enabled is True
        assert worker._scope_config.is_in_scope("http://example.com/home") is True
        assert worker._scope_config.is_in_scope("http://admin.com/") is False

    def test_scope_filter_accepts_url_string(self):
        """_scope_filter accepts string URL and matches via ScopeConfig."""
        from pwnproxy.services.proxy.proxy_worker import ProxyWorker
        import argparse
        args = argparse.Namespace(
            scope_enabled=True, scope_pattern=["*.example.com"], scope_json=None,
            listen_host="127.0.0.1", listen_port=8080,
            ssl_insecure=True, upstream=None,
            capture_enabled=True, db_path=None, confdir="~/.mitmproxy",
        )
        worker = ProxyWorker(args)
        assert worker._scope_filter("http://example.com/test?x=1") is True
        assert worker._scope_filter("http://evil.com/") is False
