from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from apps.terminal.cli.plugin_config import action_app as plugin_action_app
from apps.terminal.cli.plugin_config import config_app as plugin_config_app
from pwnproxy.plugins.core.config import get_registry_url
from pwnproxy.plugins.core.discovery import (
    discover_installed,
    install_package,
    search_pypi,
)

app = typer.Typer(help="Manage pwnproxy plugins")
console = Console()

# A plugin's own configuration lives in its own module: `config` and `action`
# talk to the API (the third client of the same contract as the Web UI and the
# MCP), while this file keeps the local package commands (search/install/list/
# create) and its templates.
app.add_typer(plugin_config_app, name="config", help="Read and write a plugin's configuration")
app.add_typer(plugin_action_app, name="action", help="Run a plugin action")



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
    """List installed packages and every plugin the catalog can load.

    Two answers to "what do I have?" used to exist: ``discover_installed`` (pip
    packages with a ``[tool.pwnproxy]`` table) and the loader's own view. Now the
    plugin catalog (built-ins + entry points) is shown next to the installed
    distributions, so a package that is installed but declares no entry point is
    visible as such instead of silently missing.
    """
    from pwnproxy.plugins.core.catalog import discover_plugins
    from pwnproxy.plugins.core.config import load_activation, plugin_enabled

    installed = discover_installed()
    catalog = discover_plugins()
    if not installed and not catalog:
        console.print("[yellow]No pwnproxy plugins installed[/yellow]")
        raise typer.Exit(0)

    if installed:
        table = Table(title="Installed Packages")
        table.add_column("Name", style="cyan")
        table.add_column("Version", style="green")
        table.add_column("Category", style="blue")
        table.add_column("Summary")
        for p in installed:
            table.add_row(
                p.get("name", ""),
                p.get("version", ""),
                p.get("category", ""),
                p.get("summary", ""),
            )
        console.print(table)

    activation = load_activation()
    catalog_table = Table(title="Plugin Catalog (built-in + installed entry points)")
    catalog_table.add_column("Name", style="cyan")
    catalog_table.add_column("Source", style="magenta")
    catalog_table.add_column("Package")
    catalog_table.add_column("Version", style="green")
    catalog_table.add_column("Enabled")
    catalog_table.add_column("Error", style="red")
    for record in catalog:
        enabled = plugin_enabled(record.name, record.source, activation)
        catalog_table.add_row(
            record.name,
            record.source,
            record.package,
            record.version,
            "yes" if enabled else ("no" if not record.error else "no (broken)"),
            record.error or "",
        )
    console.print(catalog_table)
    console.print(
        "[dim]Enable or disable a plugin with `pwnproxy plugins` in the Web UI "
        "(POST /api/v1/plugins/{name}/toggle); the state lives in "
        "~/.pwnproxy/config.toml [plugin.activation].[/dim]"
    )


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

# Declare the plugin so pwnproxy finds it after `pip install .`:
#   [project.entry-points."pwnproxy.plugins"]
#   {name} = "your_package.plugin:{name}Plugin"
# Point it at the module that actually contains the class. The entry point
# resolves to a PwnPlugin subclass (instantiated without arguments) or to an
# already built instance.

[tool.pwnproxy]
category = "{type}"
'''