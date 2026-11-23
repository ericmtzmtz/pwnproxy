import inspect
from pathlib import Path

from typer.testing import CliRunner

from apps.terminal.cli import app
from apps.terminal.cli.start import start, startup_panel_lines

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


def test_panel_carries_the_token_only_in_the_web_ui_url():
    """The panel shows `#token=` once and the file path, never the token again."""
    token = "the-api-token-0123456789abcdefghijklmnopq"
    token_path = Path("/home/user/.pwnproxy/api-token")

    lines = startup_panel_lines(
        session_name="pentest",
        host="127.0.0.1",
        proxy_port=17170,
        api_port=17171,
        web_port=17172,
        api_token=token,
        api_token_path=token_path,
        upstream=None,
        dashboard=True,
    )

    assert lines == [
        "[green]Session:[/] pentest",
        "[green]Proxy    →[/] [bold]http://127.0.0.1:17170[/]",
        "[green]API      →[/] [bold]http://127.0.0.1:17171[/]",
        "[green]API Docs →[/] [bold]http://127.0.0.1:17171/docs[/]",
        f"[green]API token →[/] [dim]{token_path}[/]",
        f"[green]Web UI   →[/] [bold]http://127.0.0.1:17172/#token={token}[/]",
        "[green]TUI dashboard[/] launched (press Q or Ctrl+Q to quit)",
    ]


def test_panel_with_env_token_omits_the_fragment_and_names_the_variable():
    """With ``PWNPROXY_API_TOKEN`` set the file token is not what the API wants.

    The server accepts the env value and ignores the file, so a fragment built
    from the file would not authenticate: print the bare URL and a note naming the
    variable, never its value (this panel can land in a CI log).
    """
    token = "file-token-0123456789abcdefghijklmnopqrst"
    token_path = Path("/home/user/.pwnproxy/api-token")

    lines = startup_panel_lines(
        session_name="pentest",
        host="127.0.0.1",
        proxy_port=17170,
        api_port=17171,
        web_port=17172,
        api_token=token,
        api_token_path=token_path,
        env_token=True,
        upstream=None,
        dashboard=False,
    )

    assert lines == [
        "[green]Session:[/] pentest",
        "[green]Proxy    →[/] [bold]http://127.0.0.1:17170[/]",
        "[green]API      →[/] [bold]http://127.0.0.1:17171[/]",
        "[green]API Docs →[/] [bold]http://127.0.0.1:17171/docs[/]",
        f"[green]API token →[/] [dim]{token_path}[/]",
        "[green]Web UI   →[/] [bold]http://127.0.0.1:17172/[/]",
        "[yellow]token:[/] PWNPROXY_API_TOKEN (from the environment; ask whoever set it)",
        "[dim]Press Ctrl+C to stop[/]",
    ]
    assert not any(token in line for line in lines)


def test_panel_without_a_token_prints_the_bare_web_ui_url():
    """Negative case: no token readable (writes refused) → no fragment, no note."""
    lines = startup_panel_lines(
        session_name=None,
        host="0.0.0.0",
        proxy_port=17170,
        api_port=17171,
        api_token=None,
        api_token_path=None,
        upstream="socks5://127.0.0.1:9050",
    )

    assert lines == [
        "[green]Session:[/] [dim](none)[/]",
        "[green]Proxy    →[/] [bold]http://0.0.0.0:17170[/]",
        "[green]API      →[/] [bold]http://0.0.0.0:17171[/]",
        "[green]API Docs →[/] [bold]http://0.0.0.0:17171/docs[/]",
        "[green]Web UI   →[/] [bold]http://127.0.0.1:17172/[/]",
        "[cyan]Upstream:[/] socks5://127.0.0.1:9050",
        "[dim]Press Ctrl+C to stop[/]",
    ]
