import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.terminal.cli import app as cli_app

runner = CliRunner()


def _create_workspace(base: Path, name: str):
    path = base / name
    path.mkdir(parents=True, exist_ok=True)
    meta = {"name": name, "created_at": "2026-01-01T00:00:00", "last_modified": "2026-01-01T00:00:00", "version": 1}
    (path / "session.json").write_text(json.dumps(meta))
    (path / "scope.json").write_text(json.dumps({"enabled": True, "in_scope": ["*.example.com"], "out_of_scope": []}))
    return base


def test_session_list():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        base = Path(tmp)
        _create_workspace(base, "alpha")
        _create_workspace(base, "beta")
        patches = (
            patch("apps.terminal.cli.session.SESSIONS_ROOT", base),
            patch("pwnproxy.services.session.manager.SESSIONS_ROOT", base),
        )
        for p in patches:
            p.start()
        try:
            result = runner.invoke(cli_app, ["session", "list"])
        finally:
            for p in patches:
                p.stop()
        assert result.exit_code == 0
        assert "alpha" in result.output
        assert "beta" in result.output


def test_session_list_empty():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        base = Path(tmp)
        patches = (
            patch("apps.terminal.cli.session.SESSIONS_ROOT", base),
            patch("pwnproxy.services.session.manager.SESSIONS_ROOT", base),
        )
        for p in patches:
            p.start()
        try:
            result = runner.invoke(cli_app, ["session", "list"])
        finally:
            for p in patches:
                p.stop()
        assert result.exit_code == 0


def test_session_info_found():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        base = Path(tmp)
        _create_workspace(base, "my-session")
        patches = (
            patch("apps.terminal.cli.session.SESSIONS_ROOT", base),
            patch("pwnproxy.services.session.manager.SESSIONS_ROOT", base),
        )
        for p in patches:
            p.start()
        try:
            result = runner.invoke(cli_app, ["session", "info", "my-session"])
        finally:
            for p in patches:
                p.stop()
        assert result.exit_code == 0
        assert "my-session" in result.output


def test_session_info_not_found():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        base = Path(tmp)
        patches = (
            patch("apps.terminal.cli.session.SESSIONS_ROOT", base),
            patch("pwnproxy.services.session.manager.SESSIONS_ROOT", base),
        )
        for p in patches:
            p.start()
        try:
            result = runner.invoke(cli_app, ["session", "info", "nonexistent"])
        finally:
            for p in patches:
                p.stop()
        assert result.exit_code != 0


def test_session_delete_found():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        base = Path(tmp)
        _create_workspace(base, "to-delete")
        patches = (
            patch("apps.terminal.cli.session.SESSIONS_ROOT", base),
            patch("pwnproxy.services.session.manager.SESSIONS_ROOT", base),
        )
        for p in patches:
            p.start()
        try:
            result = runner.invoke(cli_app, ["session", "delete", "to-delete"])
        finally:
            for p in patches:
                p.stop()
        assert result.exit_code == 0
        assert not (base / "to-delete").exists()


def test_session_delete_not_found():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        base = Path(tmp)
        patches = (
            patch("apps.terminal.cli.session.SESSIONS_ROOT", base),
            patch("pwnproxy.services.session.manager.SESSIONS_ROOT", base),
        )
        for p in patches:
            p.start()
        try:
            result = runner.invoke(cli_app, ["session", "delete", "nonexistent"])
        finally:
            for p in patches:
                p.stop()
        assert result.exit_code != 0
