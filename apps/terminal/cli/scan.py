import asyncio
import logging
import tempfile
import time
import uuid
from pathlib import Path
from typing import Optional

import httpx
import typer
from rich.console import Console

from pwnproxy.shared.models import Flow
from pwnproxy.services.findings.engine import ExportEngine
from pwnproxy.services.plugins.base import Finding
from pwnproxy.services.plugins.loader import PluginLoader
from pwnproxy.services.plugins.config import load_config

logger = logging.getLogger(__name__)
console = Console()

app = typer.Typer(help="Run standalone security scans")


@app.command()
def url(
    target: str = typer.Argument(..., help="Target URL to scan"),
    scanners: str = typer.Option("", "--scanners", "-s", help="Comma-separated scanner names (default: all active)"),
    timeout: int = typer.Option(60, "--timeout", "-t", help="Scan timeout in seconds"),
    output: str = typer.Option("json", "--output", "-o", help="Output format: json, sarif, html, pdf"),
    output_file: Optional[str] = typer.Option(None, "--output-file", "-f", help="Output file path (default: stdout)"),
):
    async def _run():
        loader = await _build_scan_loader()
        findings = await _scan_target(loader, target, timeout)
        _output_findings(findings, output, output_file)
        if findings:
            raise typer.Exit(1)

    try:
        asyncio.run(_run())
    except typer.Exit:
        pass
    except Exception as e:
        console.print(f"[red]Scan failed:[/red] {e}")
        if logger.isEnabledFor(logging.DEBUG):
            logger.exception("Scan error")
        raise typer.Exit(2)


async def _build_scan_loader() -> PluginLoader:
    from pwnproxy.services.scanners.sqli.scanner import SQLiScanner
    from pwnproxy.services.scanners.xss.scanner import XSSScanner
    from pwnproxy.services.scanners.lfi.scanner import LFIScanner
    from pwnproxy.services.scanners.xxe.scanner import XXEScanner
    from pwnproxy.services.scanners.ssrf.scanner import SSRFScanner
    from pwnproxy.services.scanners.sqli.storage import FindingStorage as SqliStorage
    from pwnproxy.services.scanners.xss.storage import XssFindingStorage as XssStorage
    from pwnproxy.services.scanners.lfi.storage import LfiFindingStorage as LfiStorage
    from pwnproxy.services.scanners.xxe.storage import XxeFindingStorage as XxeStorage
    from pwnproxy.services.scanners.ssrf.storage import SsrfFindingStorage as SsrfStorage
    from pwnproxy.services.scanners.sqli.plugin import SQLiScannerPlugin
    from pwnproxy.services.scanners.xss.plugin import XSSScannerPlugin
    from pwnproxy.services.scanners.lfi.plugin import LFIScannerPlugin
    from pwnproxy.services.scanners.xxe.plugin import XXEScannerPlugin
    from pwnproxy.services.scanners.ssrf.plugin import SSRFScannerPlugin

    tmp = tempfile.mkdtemp(prefix="pwnproxy_scan_")
    db_path = str(Path(tmp) / "results.db")
    sqli = SQLiScanner(None, storage=SqliStorage(db_path))
    xss = XSSScanner(None, storage=XssStorage(db_path))
    lfi = LFIScanner(None, storage=LfiStorage(db_path))
    xxe = XXEScanner(None, storage=XxeStorage(db_path))
    ssrf = SSRFScanner(None, storage=SsrfStorage(db_path))

    await sqli._storage.create_tables()
    await xss._storage.create_tables()
    await lfi._storage.create_tables()
    await xxe._storage.create_tables()
    await ssrf._storage.create_tables()

    loader = PluginLoader()
    await loader.load_builtin(SQLiScannerPlugin(sqli))
    await loader.load_builtin(XSSScannerPlugin(xss))
    await loader.load_builtin(LFIScannerPlugin(lfi))
    await loader.load_builtin(XXEScannerPlugin(xxe))
    await loader.load_builtin(SSRFScannerPlugin(ssrf))
    return loader


async def _scan_target(
    loader: PluginLoader,
    target: str,
    timeout: int,
    detection_depth: str = "fast",
    evasion_level: str = "none",
) -> list[Finding]:
    console.print(f"[cyan]Scanning:[/cyan] {target}")
    start = time.monotonic()

    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout), follow_redirects=True) as client:
        try:
            resp = await client.get(target)
        except Exception as e:
            console.print(f"[red]Request failed:[/red] {e}")
            raise

    parsed = httpx.URL(target)
    flow = Flow(
        id=str(uuid.uuid4()),
        method="GET",
        url=target,
        request_headers={"host": parsed.host or ""},
        request_body=None,
        status_code=resp.status_code,
        response_headers=dict(resp.headers),
        response_body=resp.content,
        duration_ms=(time.monotonic() - start) * 1000,
        tls=target.startswith("https"),
    )

    all_findings = await loader.run_scan(flow, depth=detection_depth, evasion_level=evasion_level)
    elapsed = time.monotonic() - start
    console.print(f"[cyan]Completed in[/cyan] {elapsed:.1f}s — [bold]{len(all_findings)}[/bold] finding(s)")
    return all_findings


def _output_findings(findings: list[Finding], fmt: str, output_file: Optional[str]) -> None:
    engine = ExportEngine(findings)
    result = engine.write(fmt, output_file)
    if output_file:
        console.print(f"[green]Written:[/green] {output_file}")
    else:
        print(result)
