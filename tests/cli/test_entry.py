from typer.testing import CliRunner

from pwnproxy.cli import app

runner = CliRunner()


def test_help_shows_all_commands():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for cmd in ("start", "history", "findings", "session"):
        assert cmd in result.output


def test_history_help():
    result = runner.invoke(app, ["history", "--help"])
    assert result.exit_code == 0
    assert "get" in result.output


def test_session_help():
    result = runner.invoke(app, ["session", "--help"])
    assert result.exit_code == 0
    for cmd in ("list", "info", "delete"):
        assert cmd in result.output
