import builtins
import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from pwnproxy.modules.session_manager.manager import SESSIONS_ROOT, SessionManager, ScopeConfig

console = Console()
app = typer.Typer(help="Manage proxy sessions (save/load proxy state)", no_args_is_help=True)


@app.callback(invoke_without_command=True)
def session_default(ctx: typer.Context):
    if ctx.invoked_subcommand is not None:
        return
    sessions = SessionManager.list()
    if not sessions:
        console.print("[yellow]No sessions found. Start the proxy to create one.[/]")
        return
    for s in sessions:
        console.print(f"  [cyan]{s['name']}[/]")


@app.command()
def list():
    """List all proxy sessions."""
    sessions = SessionManager.list()
    if not sessions:
        console.print("[yellow]No sessions found. Start the proxy to create one.[/]")
        return

    table = Table(title=f"Proxy Sessions ({len(sessions)})")
    table.add_column("Name", style="cyan")
    table.add_column("Created", style="dim")
    table.add_column("Last Modified", style="dim")
    table.add_column("Version")

    for s in sessions:
        created = (s.get("created_at") or "")[:19]
        modified = (s.get("last_modified") or "")[:19]
        table.add_row(
            s["name"],
            created,
            modified,
            str(s.get("version", 1)),
        )

    console.print(table)


@app.command()
def info(name: str = typer.Argument(..., help="Session name")):
    """Show detailed info about a session."""
    session_path = SESSIONS_ROOT / name
    if not session_path.exists():
        console.print(f"[red]Session '{name}' not found.[/]")
        raise typer.Exit(1)

    meta_file = session_path / "session.json"
    meta = {}
    if meta_file.exists():
        meta = json.loads(meta_file.read_text())

    scope_file = session_path / "scope.json"
    scope = {}
    if scope_file.exists():
        scope = json.loads(scope_file.read_text())

    files = builtins.list(session_path.iterdir()) if session_path.exists() else []

    text = (
        f"[bold]Name:[/] {meta.get('name', name)}\n"
        f"[bold]Created:[/] {(meta.get('created_at') or 'unknown')[:19]}\n"
        f"[bold]Last Modified:[/] {(meta.get('last_modified') or 'unknown')[:19]}\n"
        f"[bold]Version:[/] {meta.get('version', 1)}\n"
        f"[bold]Files:[/] {len(files)} ({', '.join(f.name for f in files) if files else 'none'})\n"
        f"[bold]Scope Enabled:[/] {'yes' if scope.get('enabled') else 'no'}\n"
        f"[bold]In Scope:[/] {len(scope.get('in_scope', []))} patterns\n"
        f"[bold]Out of Scope:[/] {len(scope.get('out_of_scope', []))} patterns\n"
    )
    console.print(Panel(text, title=f"Session: {name}"))


@app.command()
def delete(name: str = typer.Argument(..., help="Session name to delete")):
    """Delete a session and all its state files."""
    session_path = SESSIONS_ROOT / name
    if not session_path.exists():
        console.print(f"[red]Session '{name}' not found.[/]")
        raise typer.Exit(1)

    import shutil
    shutil.rmtree(session_path)
    console.print(f"[green]Deleted session[/] {name}")


@app.command()
def rename(
    old: str = typer.Argument(..., help="Current session name"),
    new: str = typer.Argument(..., help="New session name"),
):
    """Rename a session."""
    import asyncio
    try:
        asyncio.run(SessionManager.rename(old, new))
        console.print(f"[green]Renamed session[/] {old} -> {new}")
    except ValueError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1)
