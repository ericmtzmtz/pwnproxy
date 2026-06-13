import typer
from rich.console import Console
from rich.table import Table

from pwnproxy.plugins.core.config import load_config, get_registry_url
from pwnproxy.plugins.core.discovery import discover_installed, search_pypi, install_package

app = typer.Typer(help="Manage pwnproxy plugins")
console = Console()


@app.command()
def search(term: str = typer.Argument(..., help="Search term for finding plugins")):
    registry = get_registry_url()
    results = search_pypi(term, registry_url=registry)
    if not results:
        console.print("[yellow]No plugins found[/yellow]")
        raise typer.Exit(0)
    table = Table(title=f"Plugins matching '{term}'")
    table.add_column("Name", style="cyan")
    table.add_column("Version", style="green")
    table.add_column("Summary")
    for r in results:
        table.add_row(r.get("name", ""), r.get("version", ""), r.get("summary", ""))
    console.print(table)


@app.command()
def install(
    name: str = typer.Argument(..., help="Plugin package name to install"),
    force: bool = typer.Option(False, "--force", "-f", help="Reinstall if already installed"),
):
    success = install_package(name)
    if success:
        console.print(f"[green]Installed:[/green] {name}")
    else:
        console.print(f"[red]Failed to install:[/red] {name}")
        raise typer.Exit(1)


@app.command(name="list")
def list_plugins():
    plugins = discover_installed()
    if not plugins:
        console.print("[yellow]No pwnproxy plugins installed[/yellow]")
        raise typer.Exit(0)
    table = Table(title="Installed Plugins")
    table.add_column("Name", style="cyan")
    table.add_column("Version", style="green")
    table.add_column("Category", style="blue")
    table.add_column("Summary")
    for p in plugins:
        table.add_row(
            p.get("name", ""),
            p.get("version", ""),
            p.get("category", ""),
            p.get("summary", ""),
        )
    console.print(table)


@app.command()
def create(
    name: str = typer.Argument(..., help="Plugin name (e.g., my-custom-scanner)"),
    template: str = typer.Option("scanner", "--template", "-t", help="Plugin template type: scanner, hook"),
    dir: str = typer.Option(".", "--dir", "-d", help="Output directory"),
):
    from pathlib import Path
    out = Path(dir) / f"pwnproxy-{template}-{name}"
    if out.exists():
        console.print(f"[red]Directory already exists:[/red] {out}")
        raise typer.Exit(1)
    out.mkdir(parents=True)
    (out / "__init__.py").write_text("")
    if template == "scanner":
        (out / "plugin.py").write_text(_SCANNER_TEMPLATE.format(name=name))
    elif template == "hook":
        (out / "plugin.py").write_text(_HOOK_TEMPLATE.format(name=name))
    (out / "pyproject.toml").write_text(_PYPROJECT_TEMPLATE.format(name=name, type=template))
    console.print(f"[green]Created plugin scaffold:[/green] {out}")
    console.print("  Next: edit plugin.py and run `pip install -e .`")


_SCANNER_TEMPLATE = '''from typing import Optional
from pwnproxy.shared.models import Flow
from pwnproxy.plugins.core.base import Finding, ScannerPlugin


class {name}Plugin(ScannerPlugin):
    name = "{name}"
    version = "0.1.0"
    author = "your-name"

    async def scan(self, flow: Flow) -> Optional[Finding]:
        # Implement your scan logic here
        return None
'''

_HOOK_TEMPLATE = '''from typing import Optional
from pwnproxy.shared.models import Flow
from pwnproxy.plugins.core.base import HookPlugin


class {name}Plugin(HookPlugin):
    name = "{name}"
    version = "0.1.0"
    author = "your-name"

    async def on_request(self, flow: Flow) -> Optional[Flow]:
        # Modify or inspect request
        return flow

    async def on_response(self, flow: Flow) -> Optional[Flow]:
        # Modify or inspect response
        return flow
'''

_PYPROJECT_TEMPLATE = '''[build-system]
requires = ["setuptools", "wheel"]
build-backend = "setuptools.backends._legacy:_Backend"

[project]
name = "pwnproxy-{type}-{name}"
version = "0.1.0"
description = "pwnproxy {type} plugin: {name}"

[tool.pwnproxy]
category = "{type}"
'''
