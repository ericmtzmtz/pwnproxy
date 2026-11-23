import asyncio
import logging
import time

import typer
from rich.console import Console

from pwnproxy.plugins.core.base import Finding
from pwnproxy.plugins.core.catalog import build_scan_loader, scan_config
from pwnproxy.plugins.core.loader import PluginLoader
from pwnproxy.services.findings.engine import ExportEngine
from pwnproxy.services.scan.runner import scan_target
from pwnproxy.shared.ports import DEFAULT_CALLBACK_PORT

logger = logging.getLogger(__name__)
console = Console()

app = typer.Typer(help="Run standalone security scans")


@app.command()
def url(
    target: str = typer.Argument(..., help="Target URL to scan"),
    scanners: str = typer.Option("", "--scanners", "-s", help="Comma-separated scanner names (default: all active)"),
    timeout: int = typer.Option(60, "--timeout", "-t", help="Scan timeout in seconds"),
    output: str = typer.Option("json", "--output", "-o", help="Output format: json, sarif, html, pdf"),
    output_file: str | None = typer.Option(None, "--output-file", "-f", help="Output file path (default: stdout)"),
    cookies: list[str] | None = typer.Option(None, "--cookie", "-c", help='Cookie header, e.g. "PHPSESSID=abc; security_level=0". Repeatable.'),
    headers: list[str] | None = typer.Option(None, "--header", "-H", help='Extra header, format "Name: Value". Repeatable.'),
    method: str = typer.Option("GET", "--method", "-m", help="HTTP method for the target request (GET, POST, PUT, PATCH)"),
    data: str | None = typer.Option(None, "--data", "-d", help="Raw request body (e.g. XML or JSON payload)"),
    content_type: str | None = typer.Option(None, "--content-type", help="Content-Type header for the body (e.g. text/xml, application/json)"),
    detection_depth: str = typer.Option("fast", "--depth", help="Detection depth: fast, standard, deep"),
    evasion_level: str = typer.Option("none", "--evasion", help="Evasion level: none, light, aggressive"),
):
    async def _run():
        _cfg = scan_config(detection_depth, evasion_level)
        loader = await build_scan_loader(set(scanners.split(",")) if scanners else None, config=_cfg)
        extra_headers: dict[str, str] = {}
        if cookies:
            joined = "; ".join(c.strip().rstrip(";") for c in cookies if c and c.strip())
            if joined:
                extra_headers["Cookie"] = joined
        if headers:
            for item in headers:
                if not item or ":" not in item:
                    console.print(f"[yellow]Ignoring malformed header (expected \"Name: Value\"):[/yellow] {item}")
                    continue
                name, _, value = item.partition(":")
                extra_headers[name.strip()] = value.strip()
        body = data
        req_method = method.upper()
        if body and req_method == "GET":
            console.print("[yellow]Warning: --data ignored with --method GET. Use --method POST (or PUT/PATCH) to send a body.[/yellow]")
            body = None
        if body and content_type:
            extra_headers["Content-Type"] = content_type
        findings = await _scan_target(
            loader, target, timeout,
            method=req_method, body=body, extra_headers=extra_headers,
        )  # config is baked into loader; _scan_target no longer takes depth/evasion
        _output_findings(findings, output, output_file)
        if findings:
            raise typer.Exit(1)

    try:
        asyncio.run(_run())
    except typer.Exit as e:
        if e.exit_code:
            raise
    except Exception as e:
        console.print(f"[red]Scan failed:[/red] {e}")
        if logger.isEnabledFor(logging.DEBUG):
            logger.exception("Scan error")
        raise typer.Exit(2) from e


def _resolve_scanner_config(
    detection_depth: str = "fast",
    evasion_level: str = "none",
    callback_port: int = DEFAULT_CALLBACK_PORT,
) -> dict:
    """Deprecated alias of :func:`pwnproxy.plugins.core.catalog.scan_config`.

    Kept for one release so out-of-tree callers keep working; new code must
    import ``scan_config`` from the catalog.
    """
    return scan_config(detection_depth, evasion_level, callback_port)


async def _build_scan_loader(
    scanners: set[str] | None = None,
    disabled_plugins: list[str] | None = None,
    config: dict | None = None,
) -> PluginLoader:
    """Deprecated alias of :func:`pwnproxy.plugins.core.catalog.build_scan_loader`.

    The scanner registry used to live here as a hardcoded dict; it now comes
    from the plugin catalog (built-ins + installed entry points). Kept for one
    release so out-of-tree callers keep working.
    """
    return await build_scan_loader(scanners, disabled_plugins, config)


async def _scan_target(
    loader: PluginLoader,
    target: str,
    timeout: int,
    extra_headers: dict[str, str] | None = None,
    method: str = "GET",
    body: str | None = None,
) -> list[Finding]:
    """Print the scan banner and delegate to the shared one-shot runner."""
    console.print(f"[cyan]Scanning:[/cyan] {target}")
    start = time.monotonic()
    try:
        findings = await scan_target(
            loader, target, timeout,
            extra_headers=extra_headers, method=method, body=body,
        )
    except Exception as exc:
        console.print(f"[red]Request failed:[/red] {exc}")
        raise
    elapsed = time.monotonic() - start
    console.print(f"[cyan]Completed in[/cyan] {elapsed:.1f}s — [bold]{len(findings)}[/bold] finding(s)")
    _print_xss_scope_note(findings)
    return findings


async def _scan_target(
    loader: PluginLoader,
    target: str,
    timeout: int,
    extra_headers: dict[str, str] | None = None,
    method: str = "GET",
    body: str | None = None,
) -> list[Finding]:
    """Print the scan banner and delegate to the shared one-shot runner."""
    console.print(f"[cyan]Scanning:[/cyan] {target}")
    start = time.monotonic()
    try:
        findings = await scan_target(
            loader, target, timeout,
            extra_headers=extra_headers, method=method, body=body,
        )
    except Exception as exc:
        console.print(f"[red]Request failed:[/red] {exc}")
        raise
    elapsed = time.monotonic() - start
    console.print(f"[cyan]Completed in[/cyan] {elapsed:.1f}s — [bold]{len(findings)}[/bold] finding(s)")
    _print_xss_scope_note(findings)
    return findings


def _print_xss_scope_note(findings: list[Finding]) -> None:
    """Declare the XSS detector's coverage scope instead of implying absence
    means the surface is XSS-free (task 7.1)."""
    if any(f.technique == "reflected-xss" for f in findings):
        return
    console.print(
        "[dim]Note: no reflected-XSS reported. The XSS scanner only flags exploitable "
        "breakouts (unescaped markup / attribute, JS string, URI, comment, SVG); "
        "absence of a finding does NOT guarantee the surface is XSS-free, only that "
        "no reflectable breakout was confirmed in the declared contexts.[/dim]"
    )


def _output_findings(findings: list[Finding], fmt: str, output_file: str | None) -> None:
    engine = ExportEngine(findings)
    result = engine.write(fmt, output_file)
    if output_file:
        console.print(f"[green]Written:[/green] {output_file}")
    else:
        print(result)
