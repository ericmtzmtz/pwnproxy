import typer

from apps.terminal.cli.start import start
from apps.terminal.cli.history import app as history_app
from apps.terminal.cli.findings import findings
from apps.terminal.cli.session import app as session_app
from apps.terminal.cli.tokens import app as tokens_app
from apps.terminal.cli.plugin import app as plugin_app
from apps.terminal.cli.scan import app as scan_app
from apps.terminal.cli.import_cmd import app as import_app

app = typer.Typer(
    name="pwnproxy",
    help="Open source Burp Suite alternative for terminal",
    no_args_is_help=True,
)

app.command()(start)
app.add_typer(history_app, name="history", help="Query proxy traffic history")
app.add_typer(session_app, name="session", help="Manage proxy sessions (save/load state)")
app.add_typer(tokens_app, name="tokens", help="Manage extracted tokens (JWT, cookies, CSRF)")
app.add_typer(plugin_app, name="plugin", help="Manage pwnproxy plugins")
app.add_typer(scan_app, name="scan", help="Run standalone security scans")
app.add_typer(import_app, name="import", help="Import configurations from other tools")
app.command()(findings)


if __name__ == "__main__":
    app()
