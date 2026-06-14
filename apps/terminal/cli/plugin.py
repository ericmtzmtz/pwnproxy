import typer
from pathlib import Path
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
    template: str = typer.Option(
        "scanner",
        "--template",
        "-t",
        help="Plugin template type: scanner, crawler, exploiter, hook",
        case_sensitive=False,
    ),
    dir: str = typer.Option(".", "--dir", "-d", help="Output directory"),
):
    """
    Scaffold a new plugin based on the selected template.
    """
    tmpl = template.lower()
    valid_templates = {"scanner", "crawler", "exploiter", "hook"}
    if tmpl not in valid_templates:
        console.print(f"[red]Unknown template '{template}'.[/red] Choose from: {', '.join(sorted(valid_templates))}")
        raise typer.Exit(1)

    out = Path(dir) / f"pwnproxy-{tmpl}-{name}"
    if out.exists():
        console.print(f"[red]Directory already exists:[/red] {out}")
        raise typer.Exit(1)

    out.mkdir(parents=True)
    (out / "__init__.py").write_text("")
    (out / "plugin.py").write_text(_TEMPLATES[tmpl].format(name=name))
    (out / "pyproject.toml").write_text(_PYPROJECT_TEMPLATE.format(name=name, type=tmpl))

    console.print(f"[green]Created plugin scaffold:[/green] {out}")
    console.print("  Next: edit plugin.py and run `pip install -e .`")


# -- Templates ------------------------------------------------------------------

_SCANNER_TEMPLATE = '''\
from pwnproxy.plugins.core.base import PluginMetadata, Finding, ScannerPlugin
from pwnproxy.shared.models import Flow

class {name}Plugin(ScannerPlugin):
    metadata = PluginMetadata(
        name="{name}",
        version="0.1.0",
        author="your-name",
        consumes=["flow"],
        produces=["finding"],
    )

    async def on_flow(self, flow: Flow):
        depth = self.context.config.get("depth", "fast")
        evasion_level = self.context.config.get("evasion_level", "none")
        # TODO: Implement scanning logic
        ...
        yield Finding(
            scanner="{name}",
            url=flow.url,
            method=flow.method,
            param_name="param",
            param_location="query",
            technique="detection-technique",
            severity="medium",
            confidence="tentative",
            payload="payload",
            evidence="evidence",
        )
''' 

_HOOK_TEMPLATE = '''\
from pwnproxy.plugins.core.base import PluginMetadata, HookPlugin
from pwnproxy.shared.models import Flow

class {name}Plugin(HookPlugin):
    metadata = PluginMetadata(
        name="{name}",
        version="0.1.0",
        author="your-name",
        consumes=["flow"],
        produces=[],
    )

    async def on_request(self, flow: Flow) -> Flow:
        # TODO: Modify or inspect request
        return flow

    async def on_response(self, flow: Flow) -> Flow:
        # TODO: Modify or inspect response
        return flow
''' 

_CRAWLER_TEMPLATE = '''\
from pwnproxy.plugins.core.base import PluginMetadata, CrawlerPlugin
from pwnproxy.plugins.core.types import Surface

class {name}Plugin(CrawlerPlugin):
    metadata = PluginMetadata(
        name="{name}",
        version="0.1.0",
        author="your-name",
        consumes=["surface"],
        produces=["surface"],
    )

    async def on_surface(self, surface: Surface) -> Surface | None:
        # TODO: Crawl the surface and return new surfaces
        return surface
''' 

_EXPLOITER_TEMPLATE = '''\
from pwnproxy.plugins.core.base import PluginMetadata, ExploiterPlugin, Finding
from pwnproxy.plugins.core.types import Evidence

class {name}Plugin(ExploiterPlugin):
    metadata = PluginMetadata(
        name="{name}",
        version="0.1.0",
        author="your-name",
        consumes=["evidence"],
        produces=["finding"],
    )

    async def on_evidence(self, evidence: Evidence) -> Finding | None:
        # TODO: Exploit the evidence to confirm the finding
        return None
''' 

_TEMPLATES = {
    "scanner": _SCANNER_TEMPLATE,
    "crawler": _CRAWLER_TEMPLATE,
    "exploiter": _EXPLOITER_TEMPLATE,
    "hook": _HOOK_TEMPLATE,
}

_PYPROJECT_TEMPLATE = '''\
[build-system]
requires = ["setuptools", "wheel"]
build-backend = "setuptools.backends._legacy:_Backend"

[project]
name = "pwnproxy-{type}-{name}"
version = "0.1.0"
description = "pwnproxy {type} plugin: {name}"

[tool.pwnproxy]
category = "{type}"
'''