"""Rendering: Markdown is the intermediate representation; HTML/PDF derive from it."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATES_DIR = Path(__file__).parent / "templates"

_env = Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    autoescape=select_autoescape(default=False),
    trim_blocks=True,
    lstrip_blocks=True,
)


def render_markdown(context: dict[str, Any]) -> str:
    template = _env.get_template("base.md.j2")
    return template.render(**context)


def markdown_to_html(markdown_text: str) -> str:
    try:
        import markdown as _markdown
    except ImportError as e:
        raise RuntimeError(
            "The 'markdown' package is required to derive HTML reports. "
            "Install it with: poetry add markdown (or pip install markdown)"
        ) from e
    return _markdown.markdown(markdown_text, extensions=["tables", "fenced_code"])


def render_html(context: dict[str, Any], markdown_text: str) -> str:
    body = markdown_to_html(markdown_text)
    template = _env.get_template("base.html.j2")
    return template.render(**context, body=body)


def render_pdf(html_text: str, out_path: Path) -> Path:
    try:
        from weasyprint import HTML
    except ImportError as e:
        raise RuntimeError(
            "weasyprint is not installed, so PDF export is unavailable. "
            "MD and HTML formats still work. Install the optional extra with: "
            "pip install 'pwnproxy[reports-pdf]'"
        ) from e
    except OSError as e:
        # WeasyPrint is installed but its native GTK/Pango DLLs are missing
        # (common on Windows; pip does not ship them). Distinguish from a
        # plain "not installed" so the user gets an actionable message.
        raise RuntimeError(
            "weasyprint is installed but cannot load its native libraries "
            "(GTK/Pango runtime). MD and HTML formats still work. On Windows, "
            "install the GTK3 Runtime Environment (see "
            "https://doc.courtbouillon.org/weasyprint/stable/first_steps.html) "
            "and restart pwnproxy."
        ) from e
    HTML(string=html_text).write_pdf(str(out_path))
    return out_path
