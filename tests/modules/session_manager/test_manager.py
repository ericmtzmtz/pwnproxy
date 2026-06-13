import tempfile
from pathlib import Path

import pytest

from pwnproxy.services.session.manager import ScopeConfig, SessionManager, SESSIONS_ROOT


@pytest.fixture
def mock_sessions_root(monkeypatch, tmp_path):
    monkeypatch.setattr("pwnproxy.services.session.manager.SESSIONS_ROOT", tmp_path)
    monkeypatch.setattr("pwnproxy.services.session.manager.LAST_SESSION_FILE", tmp_path / ".last_session")
    return tmp_path


class TestScopeConfig:
    def test_enabled_false_passes_all(self):
        scope = ScopeConfig({"enabled": False, "in_scope": ["*.target.com"]})
        assert scope.is_in_scope("https://evil.com/test")

    def test_in_scope_matches_domain(self):
        scope = ScopeConfig({"enabled": True, "in_scope": ["*.target.com"]})
        assert scope.is_in_scope("https://api.target.com/endpoint")
        assert not scope.is_in_scope("https://evil.com/test")

    def test_in_scope_matches_url_pattern(self):
        scope = ScopeConfig({"enabled": True, "in_scope": ["https://api.target.com/*"]})
        assert scope.is_in_scope("https://api.target.com/v1/users")
        assert not scope.is_in_scope("https://other.target.com/test")

    def test_out_of_scope_excludes(self):
        scope = ScopeConfig({
            "enabled": True,
            "in_scope": ["*.target.com"],
            "out_of_scope": ["https://analytics.target.com/*"],
        })
        assert scope.is_in_scope("https://api.target.com/endpoint")
        assert not scope.is_in_scope("https://analytics.target.com/report")

    def test_no_in_scope_patterns_passes_all(self):
        scope = ScopeConfig({"enabled": True, "in_scope": []})
        assert scope.is_in_scope("https://anything.com/test")

    def test_to_dict_roundtrip(self):
        data = {
            "enabled": True,
            "in_scope": ["*.target.com"],
            "out_of_scope": ["https://ads.target.com"],
            "include_subdomains": True,
            "ports": [80, 443],
        }
        scope = ScopeConfig(data)
        assert scope.to_dict() == data


def test_list_empty(mock_sessions_root):
    assert SessionManager.list() == []


def test_list_after_create(mock_sessions_root):
    session_dir = mock_sessions_root / "test-session"
    session_dir.mkdir(parents=True)
    (session_dir / "session.json").write_text('{"name": "test-session", "version": 1}')

    result = SessionManager.list()
    names = [s["name"] for s in result]
    assert "test-session" in names


def test_scope_config_url_without_scheme(mock_sessions_root):
    scope = ScopeConfig({"enabled": True, "in_scope": ["*.target.com"]})
    assert not scope.is_in_scope("http://evil.com/test")
    assert scope.is_in_scope("http://sub.target.com/test")
