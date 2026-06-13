import json
import logging
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

logger = logging.getLogger(__name__)
console = Console()

app = typer.Typer(help="Import configurations from other tools")


@app.command()
def burp(
    config: str = typer.Argument(..., help="Path to Burp Suite project JSON config file"),
    out: Optional[str] = typer.Option(None, "--out", "-o", help="Output pwnproxy scope config path"),
):
    path = Path(config)
    if not path.exists():
        console.print(f"[red]File not found:[/red] {path}")
        raise typer.Exit(1)

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        console.print(f"[red]Invalid JSON:[/red] {e}")
        raise typer.Exit(1)

    scope = _parse_burp_scope(data)
    if not scope:
        console.print("[yellow]No scope configuration found in Burp config[/yellow]")
        raise typer.Exit(0)

    _write_scope(scope, out)
    console.print(f"[green]Imported {len(scope['include'])} inclusions, {len(scope['exclude'])} exclusions[/green]")
    if out:
        console.print(f"[green]Written to:[/green] {out}")


def _parse_burp_scope(data: dict) -> Optional[dict]:
    target = data.get("target", {})
    scope = target.get("scope", {})
    if not scope:
        scope = data.get("scope", {})

    include_raw = scope.get("include", scope.get("in_scope", []))
    exclude_raw = scope.get("exclude", scope.get("out_of_scope", []))

    include = [_parse_url_rule(r) for r in include_raw if isinstance(r, dict)]
    exclude = [_parse_url_rule(r) for r in exclude_raw if isinstance(r, dict)]

    if not include and not exclude:
        return None

    return {
        "include": [i for i in include if i],
        "exclude": [e for e in exclude if e],
    }


import re

_REGEX_META = re.compile(r"\\.|[.*+?^${}()|[\]\\\\]")


def _strip_regex(s: str) -> str:
    return s.removeprefix("^").removesuffix("$")


def _unescape_regex(s: str) -> str:
    return s.replace("\\.", ".").replace("\\/", "/").replace("\\*", "*")


def _parse_url_rule(rule: dict) -> Optional[str]:
    if "prefix" in rule:
        return rule["prefix"]
    if "url" in rule:
        return rule["url"]
    if "pattern" in rule:
        return rule["pattern"]

    protocol = rule.get("protocol", "")
    host = rule.get("host", "")
    port = rule.get("port", "")
    file_pattern = rule.get("file", "")

    if not host:
        return None

    host_clean = _unescape_regex(_strip_regex(host))
    file_clean = _unescape_regex(_strip_regex(file_pattern)) if file_pattern else "/*"

    if not file_clean.startswith("/"):
        file_clean = "/*"

    port_suffix = ""
    if port:
        port_clean = _unescape_regex(_strip_regex(port))
        if port_clean not in ("80", "443", ""):
            port_suffix = f":{port_clean}"

    return f"{protocol}://{host_clean}{port_suffix}{file_clean}"


def _write_scope(scope: dict, out_path: Optional[str] = None) -> None:
    if out_path:
        out = Path(out_path)
    else:
        out = Path.home() / ".pwnproxy" / "burp_scope.json"

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(scope, indent=2), encoding="utf-8")
