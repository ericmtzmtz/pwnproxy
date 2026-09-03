import inspect

from typer.testing import CliRunner

from apps.terminal.cli import app
from apps.terminal.cli.start import start

runner = CliRunner()


def _option_names(param_name: str) -> list[str]:
    """Return the CLI option names (--x / -x) declared on a start() parameter."""
    default = inspect.signature(start).parameters[param_name].default
    # typer.Option(..., *names) → the option names are positional args before
    # the help kwarg; typer stores them on the default's .param_decls.
    decls = getattr(default, "param_decls", None)
    return list(decls) if decls else []


def test_start_help_exits_zero():
    """--help on the start command exits 0 (rendering may vary by platform)."""
    result = runner.invoke(app, ["start", "--help"])
    assert result.exit_code == 0


def test_start_declares_proxy_and_api_port_options():
    """--proxy-port / --api-port must exist as options on the start command.

    Asserted against the callback signature rather than the rich-rendered help
    text, which varies by terminal width/ANSI support across platforms and CI.
    """
    proxy = _option_names("proxy_port")
    api = _option_names("api_port")
    assert "--proxy-port" in proxy
    assert "--api-port" in api
