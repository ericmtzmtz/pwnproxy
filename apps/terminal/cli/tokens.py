import asyncio

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from pwnproxy.services.session.storage import TokenStorage

console = Console()
app = typer.Typer(help="Manage extracted tokens (JWT, cookies, CSRF)", no_args_is_help=True)


@app.callback(invoke_without_command=True)
def tokens_default(ctx: typer.Context):
    if ctx.invoked_subcommand is not None:
        return
    asyncio.run(_list_tokens(None))


async def _list_tokens(token_type: str | None):
    storage = TokenStorage()
    await storage.init()
    tokens = await storage.query(token_type=token_type)
    await storage.close()

    if not tokens:
        console.print("[yellow]No tokens found.[/]")
        return

    table = Table(title=f"Tokens ({len(tokens)})")
    table.add_column("ID", style="dim")
    table.add_column("Type", style="cyan")
    table.add_column("Hash", style="dim")
    table.add_column("Label")
    table.add_column("Status")
    table.add_column("Last Seen", style="dim")

    for t in tokens:
        table.add_row(
            str(t.id),
            t.token_type,
            t.token_hash[:16] + "...",
            t.label or "",
            t.status or "unknown",
            str(t.last_seen)[:19],
        )

    console.print(table)


@app.command()
def list(
    type: str = typer.Option(None, "--type", "-t", help="Filter by token type (jwt, cookie, csrf)"),
):
    asyncio.run(_list_tokens(type))


@app.command()
def get(token_id: int = typer.Argument(..., help="Token ID")):
    asyncio.run(_get_token(token_id))


async def _get_token(token_id: int):
    storage = TokenStorage()
    await storage.init()
    token = await storage.get_by_id(token_id)
    await storage.close()

    if token is None:
        console.print(f"[red]Token {token_id} not found.[/]")
        raise typer.Exit(1)

    info = (
        f"[bold]ID:[/] {token.id}\n"
        f"[bold]Type:[/] {token.token_type}\n"
        f"[bold]Label:[/] {token.label or '—'}\n"
        f"[bold]Status:[/] {token.status or 'unknown'}\n"
        f"[bold]Source URL:[/] {token.source_url or '—'}\n"
        f"[bold]First Seen:[/] {token.first_seen}\n"
        f"[bold]Last Seen:[/] {token.last_seen}\n"
        f"[bold]Ref Count:[/] {token.ref_count}\n"
    )
    console.print(Panel(info, title=f"Token #{token.id}"))

    from rich.syntax import Syntax
    console.print(Panel(Syntax(token.token_value[:2000], "text", theme="monokai"), title="Token Value"))


@app.command()
def delete(token_id: int = typer.Argument(..., help="Token ID to delete")):
    asyncio.run(_delete_token(token_id))


async def _delete_token(token_id: int):
    storage = TokenStorage()
    await storage.init()
    deleted = await storage.delete_by_id(token_id)
    await storage.close()

    if not deleted:
        console.print(f"[red]Token {token_id} not found.[/]")
        raise typer.Exit(1)

    console.print(f"[green]Deleted token[/] {token_id}")
