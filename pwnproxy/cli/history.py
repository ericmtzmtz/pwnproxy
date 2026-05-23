import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from pwnproxy.core.db import FlowRecord

console = Console()
app = typer.Typer(help="Query proxy traffic history")


def _get_engine():
    db_path = Path.home() / ".pwnproxy" / "traffic.db"
    return create_async_engine(f"sqlite+aiosqlite:///{db_path.absolute()}", echo=False)


@app.callback(invoke_without_command=True)
def history_default(ctx: typer.Context, limit: int = typer.Option(10, "--limit", "-n", help="Number of flows to show")):
    if ctx.invoked_subcommand is not None:
        return
    asyncio.run(_list_flows(limit))


async def _list_flows(limit: int):
    engine = _get_engine()
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        result = await session.execute(
            select(FlowRecord).order_by(FlowRecord.timestamp.desc()).limit(limit)
        )
        flows = result.scalars().all()
    await engine.dispose()

    if not flows:
        console.print("[yellow]No flows found.[/]")
        return

    table = Table(title=f"Recent Flows (last {len(flows)})")
    table.add_column("ID", style="dim")
    table.add_column("Method", style="cyan")
    table.add_column("URL")
    table.add_column("Status", style="green")
    table.add_column("Timestamp", style="dim")

    for f in flows:
        table.add_row(str(f.id), f.method, f.url[:80], str(f.status_code or ""), str(f.timestamp)[:19])

    console.print(table)


@app.command()
def get(flow_id: int = typer.Argument(..., help="Flow ID")):
    asyncio.run(_get_flow(flow_id))


async def _get_flow(flow_id: int):
    engine = _get_engine()
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        result = await session.execute(
            select(FlowRecord).where(FlowRecord.id == flow_id)
        )
        flow = result.scalar_one_or_none()
    await engine.dispose()

    if flow is None:
        console.print(f"[red]Flow {flow_id} not found.[/]")
        raise typer.Exit(1)

    from rich.panel import Panel
    from rich.syntax import Syntax

    req_headers = "\n".join(f"{k}: {v}" for k, v in (flow.request_headers or {}).items())
    req_text = f"{flow.method} {flow.url}\n{req_headers}"
    if flow.request_body:
        body_preview = flow.request_body[:1000].decode("utf-8", "replace")
        req_text += f"\n\n{body_preview}"

    console.print(Panel(Syntax(req_text, "http", theme="monokai"), title=f"Request [{flow.method}]"))

    resp_headers = "\n".join(f"{k}: {v}" for k, v in (flow.response_headers or {}).items())
    resp_text = f"HTTP {flow.status_code or '???'}\n{resp_headers}"
    if flow.response_body:
        body_preview = flow.response_body[:2000].decode("utf-8", "replace")
        resp_text += f"\n\n{body_preview}"

    console.print(Panel(Syntax(resp_text, "http", theme="monokai"), title=f"Response [{flow.status_code}]"))
