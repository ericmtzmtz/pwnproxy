import typer

from pwnproxy.cli.start import start
from pwnproxy.cli.history import app as history_app
from pwnproxy.cli.findings import findings
from pwnproxy.cli.session import app as session_app
from pwnproxy.cli.tokens import app as tokens_app
from pwnproxy.cli.plugin import app as plugin_app
from pwnproxy.cli.scan import app as scan_app
from pwnproxy.cli.import_cmd import app as import_app

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
