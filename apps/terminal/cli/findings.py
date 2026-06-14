import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from pwnproxy.shared.findings.storage import FindingORM

VALID_SCANNERS = ["sqli", "xss", "lfi", "xxe", "ssrf"]

console = Console()


def _get_engine():
    db_path = Path.home() / ".pwnproxy" / "scanner_results.db"
    return create_async_engine(f"sqlite+aiosqlite:///{db_path.absolute()}", echo=False)


def findings(
    scanner: str = typer.Option(None, "--scanner", "-s", help="Filter by scanner type"),
    limit: int = typer.Option(20, "--limit", "-n", help="Max findings to show"),
):
    if scanner and scanner not in VALID_SCANNERS:
        console.print(f"[red]Unknown scanner:[/] {scanner}")
        console.print(f"[yellow]Available:[/] {', '.join(VALID_SCANNERS)}")
        raise typer.Exit(1)
    asyncio.run(_list_findings(scanner, limit))


async def _list_findings(scanner: str | None, limit: int):
    engine = _get_engine()
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    all_findings = []

    async with factory() as session:
        try:
            query = select(FindingORM)
            if scanner:
                query = query.where(FindingORM.scanner == scanner)
            query = query.order_by(FindingORM.id.desc()).limit(limit)
            result = await session.execute(query)
            rows = result.scalars().all()
            for r in rows:
                item = {c.name: getattr(r, c.name) for c in FindingORM.__table__.columns}
                all_findings.append(item)
        except Exception:
            pass

    await engine.dispose()

    if not all_findings:
        if scanner:
            console.print(f"[yellow]No findings for scanner:[/] {scanner}")
        else:
            console.print("[yellow]No findings found.[/]")
        return

    table = Table(title=f"Scanner Findings ({len(all_findings)})")
    table.add_column("ID", style="dim")
    table.add_column("Scanner", style="cyan")
    table.add_column("URL")
    table.add_column("Param", style="yellow")
    table.add_column("Payload", style="magenta")
    table.add_column("Severity", style="red")

    for f in all_findings:
        table.add_row(
            str(f.get("id", "")),
            f.get("scanner", ""),
            (f.get("url", "") or "")[:60],
            f.get("param_name", "") or "",
            (f.get("payload", "") or "")[:40],
            f.get("severity", "medium"),
        )

    console.print(table)