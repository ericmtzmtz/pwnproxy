import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from pwnproxy.shared.findings.storage import FindingORM

console = Console()

#: Column width used to print the scanner names present in the database.
_HELP_SCANNER_LIMIT = 10


def _get_engine():
    db_path = Path.home() / ".pwnproxy" / "scanner_results.db"
    return create_async_engine(f"sqlite+aiosqlite:///{db_path.absolute()}", echo=False)


def findings(
    scanner: str = typer.Option(
        None, "--scanner", "-s",
        help="Filter by scanner name (free text; see the names present in the database)",
    ),
    limit: int = typer.Option(20, "--limit", "-n", help="Max findings to show"),
):
    """List findings, optionally filtered by a scanner name.

    ``--scanner`` is free text on purpose: the set of scanners comes from the
    plugin catalog (built-ins plus installed plugins), so validating against a
    hardcoded list here would hide every third-party finding.
    """
    asyncio.run(_list_findings(scanner, limit))


async def _present_scanners(engine) -> list[str]:
    """Return the distinct ``scanner`` values stored in the database."""
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        try:
            result = await session.execute(select(FindingORM.scanner).distinct())
            return sorted(row[0] for row in result.all() if row[0])
        except Exception:
            return []


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

    present = await _present_scanners(engine)
    await engine.dispose()

    if not all_findings:
        if scanner:
            console.print(f"[yellow]No findings for scanner:[/] {scanner}")
            if present:
                console.print(
                    f"[dim]Scanners present in this database: {', '.join(present[:_HELP_SCANNER_LIMIT])}[/dim]"
                )
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