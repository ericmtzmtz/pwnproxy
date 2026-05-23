import typer

from pwnproxy.cli.start import start
from pwnproxy.cli.history import app as history_app
from pwnproxy.cli.findings import findings
from pwnproxy.cli.session import app as session_app

app = typer.Typer(
    name="pwnproxy",
    help="Open source Burp Suite alternative for terminal",
    no_args_is_help=True,
)

app.command()(start)
app.add_typer(history_app, name="history", help="Query proxy traffic history")
app.add_typer(session_app, name="session", help="Manage stored sessions")
app.command()(findings)


if __name__ == "__main__":
    app()
