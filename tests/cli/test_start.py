from typer.testing import CliRunner

from pwnproxy.cli import app

runner = CliRunner()


def test_start_help():
    result = runner.invoke(app, ["start", "--help"])
    assert result.exit_code == 0
    assert "--proxy-port" in result.output
    assert "--api-port" in result.output
