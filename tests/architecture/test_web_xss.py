"""Guards that keep third-party data out of the DOM as markup.

The Web UI keeps the API token in ``localStorage``, so one script running on
its origin owns everything the proxy can reach: every captured flow, every
finding, every session. And the UI is full of data controlled by the scanned
target — response bodies, URLs, headers, parameters, payloads and the server's
own error messages.

Three rules, all textual on purpose (an AST walk from Python cannot see inside
an Astro ``<script>`` block, a JSX attribute or a template string):

1. **Responses render in an opaque origin** (:class:`TestResponseIframes`).
   Every ``<iframe`` carries ``sandbox=""`` — empty on purpose — plus
   ``referrerpolicy="no-referrer"``. ``srcdoc`` inherits the page origin, so
   without an empty allow-list a target's ``<script>`` reads
   ``localStorage['pwnproxy.api.token']``. ``allow-scripts`` and
   ``allow-same-origin`` must never come back.
2. **No HTML built from data** (:class:`TestNoHtmlSinks`). ``insertAdjacentHTML``,
   ``outerHTML =`` and a non-empty ``innerHTML =`` are forbidden;
   ``dangerouslySetInnerHTML`` is allowed only on a line that goes through
   ``highlightBody``, the single function that escapes *before* writing markup.
3. **One escape helper, escaping first** (:class:`TestEscapeHelper`). The
   duplicated ``div.textContent -> d.innerHTML`` helpers are gone; if escaping is
   ever needed again it comes from ``utils/escape.ts``.

A violation is reported as ``archivo:línea (texto de la línea)``. The allow-list
is a single source-level condition (rule 2), never a file: a new page that needs
to show data creates nodes and sets ``textContent`` (``@/utils/dom``).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
WEB_SRC = REPO_ROOT / "apps" / "web" / "src"

#: The only module allowed to turn data into HTML (escaping first).
ESCAPE_MODULE = Path("utils") / "escape.ts"
ESCAPE_TS = WEB_SRC / ESCAPE_MODULE

#: The component that renders target responses (Repeater).
RESPONSE_VIEWER = Path("components") / "repeater" / "ResponseViewer.tsx"

#: Build output and installed dependencies carry vendored copies of everything.
PRUNED_DIR_NAMES = {"node_modules", "dist", ".astro", "__pycache__", ".vite"}

#: Suffixes that can hold DOM code.
SCANNED_SUFFIXES = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".astro"}

IFRAME_OPEN = re.compile(r"<iframe\b", re.IGNORECASE)
SANDBOX_ATTR = re.compile(r"sandbox\s*=\s*(?P<value>\"[^\"]*\"|'[^']*')", re.IGNORECASE)
REFERRER_NONE = re.compile(r"referrerpolicy\s*=\s*\"no-referrer\"", re.IGNORECASE)

INNER_HTML_ASSIGN = re.compile(r"\.innerHTML\s*=\s*(?P<rhs>.*)")
OUTER_HTML_ASSIGN = re.compile(r"\.outerHTML\s*=")
INSERT_ADJACENT = re.compile(r"\binsertAdjacentHTML\s*\(")
SET_HTML_DIRECTIVE = re.compile(r"\bset:html\s*=")

#: The JSX prop that injects raw HTML.
DANGEROUS_PROP = "dangerouslySetInnerHTML"

#: Only this call may feed an HTML sink, and it escapes before it marks up.
SAFE_SINK_CALL = "highlightBody("

ESCAPE_FUNCTION = re.compile(r"(?:export\s+)?function\s+escapeHtml\s*\(")


def _iter_web_files(root: Path = WEB_SRC) -> list[Path]:
    """Every source file the guards inspect, sorted for a stable message."""
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in PRUNED_DIR_NAMES for part in path.parts):
            continue
        if path.suffix.lower() not in SCANNED_SUFFIXES:
            continue
        files.append(path)
    return sorted(files)


def _display(path: Path) -> str:
    """Repo-relative path when possible, absolute otherwise (mutation trees)."""
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return ""


def _is_empty_rhs(rhs: str) -> bool:
    """``innerHTML = ""`` (clearing) is fine; anything else is not."""
    return rhs.strip().startswith('""') or rhs.strip().startswith("''")


def _html_sinks(root: Path = WEB_SRC) -> list[str]:
    """Lines that can turn data into markup, reported as ``archivo:línea (…)``."""
    violations: list[str] = []
    for path in _iter_web_files(root):
        text = _read(path)
        for lineno, line in enumerate(text.splitlines(), start=1):
            hit = (
                INSERT_ADJACENT.search(line)
                or OUTER_HTML_ASSIGN.search(line)
                or SET_HTML_DIRECTIVE.search(line)
            )
            if hit:
                violations.append(f"{_display(path)}:{lineno} ({line.strip()})")
                continue
            assignment = INNER_HTML_ASSIGN.search(line)
            if assignment and not _is_empty_rhs(assignment.group("rhs")):
                violations.append(f"{_display(path)}:{lineno} ({line.strip()})")
                continue
            if DANGEROUS_PROP in line and SAFE_SINK_CALL not in line:
                violations.append(f"{_display(path)}:{lineno} ({line.strip()})")
    return violations


def _iframe_tags(root: Path = WEB_SRC) -> list[tuple[Path, int, str]]:
    """``(archivo, línea, etiqueta completa)`` for every ``<iframe`` in the tree."""
    tags: list[tuple[Path, int, str]] = []
    for path in _iter_web_files(root):
        text = _read(path)
        for match in IFRAME_OPEN.finditer(text):
            end = text.find(">", match.start())
            if end == -1:
                end = len(text)
            tag = text[match.start() : end + 1]
            tags.append((path, text.count("\n", 0, match.start()) + 1, tag))
    return tags


def _unsandboxed_iframes(root: Path = WEB_SRC) -> list[str]:
    """Iframes whose sandbox is missing, non-empty, or whose referrer leaks."""
    violations: list[str] = []
    for path, lineno, tag in _iframe_tags(root):
        problems: list[str] = []
        sandbox = SANDBOX_ATTR.search(tag)
        if sandbox is None:
            problems.append('falta sandbox=""')
        elif sandbox.group("value") not in {'""', "''"}:
            problems.append(f"sandbox no vacío ({sandbox.group('value')})")
        if not REFERRER_NONE.search(tag):
            problems.append('falta referrerpolicy="no-referrer"')
        if problems:
            flattened = " ".join(tag.split())
            violations.append(f"{_display(path)}:{lineno} ({'; '.join(problems)} → {flattened})")
    return violations


class TestResponseIframes:
    def test_every_response_iframe_is_sandboxed_to_an_opaque_origin(self):
        violations = _unsandboxed_iframes()
        assert violations == [], (
            "Cada <iframe que muestra una respuesta del objetivo lleva "
            '`sandbox=""` (allow-list vacía: origen opaco) y '
            '`referrerpolicy="no-referrer"`. Un `srcdoc` hereda el origen de la '
            "UI, así que `allow-scripts`/`allow-same-origin` dejan que el "
            "objetivo lea el token de localStorage. Offenders:\n"
            + "\n".join(violations)
        )

    def test_guard_detects_a_missing_or_weakened_sandbox(self, tmp_path):
        (tmp_path / "pages").mkdir()
        (tmp_path / "pages" / "Bare.astro").write_text(
            "<iframe srcDoc={body} />\n"
            '<iframe sandbox="allow-same-origin" referrerpolicy="no-referrer" srcdoc={body} />\n'
            '<iframe sandbox="" referrerpolicy="no-referrer" srcdoc={body} />\n'
            '<iframe sandbox="" srcdoc={body} />\n',
            encoding="utf-8",
        )
        violations = _unsandboxed_iframes(root=tmp_path)
        assert [v.split(" (")[0] for v in violations] == [
            f"{tmp_path.as_posix()}/pages/Bare.astro:1",
            f"{tmp_path.as_posix()}/pages/Bare.astro:2",
            f"{tmp_path.as_posix()}/pages/Bare.astro:4",
        ]


class TestNoHtmlSinks:
    def test_no_html_is_built_from_data(self):
        violations = _html_sinks()
        assert violations == [], (
            "Nada de HTML construido con datos: usa `textContent` o los nodos de "
            "`@/utils/dom` (`el`, `svgIcon`). Se prohíben insertAdjacentHTML, "
            "`outerHTML =`, `set:html` y toda asignación `.innerHTML =` que no "
            "sea `\"\"`; `dangerouslySetInnerHTML` solo se admite en la línea "
            f"que llama a `{SAFE_SINK_CALL}`. Offenders:\n" + "\n".join(violations)
        )

    def test_guard_detects_each_forbidden_shape(self, tmp_path):
        (tmp_path / "components").mkdir()
        (tmp_path / "components" / "Page.tsx").write_text(
            'list.innerHTML = "";\n'
            "list.innerHTML = `<div>${flow.url}</div>`;\n"
            "node.insertAdjacentHTML('beforeend', payload);\n"
            "node.outerHTML = payload;\n"
            "const html = <div dangerouslySetInnerHTML={{ __html: body }} />;\n"
            "const ok = <pre dangerouslySetInnerHTML={{ __html: highlightBody(body, ct) }} />;\n",
            encoding="utf-8",
        )
        (tmp_path / "pages").mkdir()
        (tmp_path / "pages" / "Raw.astro").write_text(
            "<p set:html={f.message} />\n",
            encoding="utf-8",
        )
        violations = _html_sinks(root=tmp_path)
        assert [v.split(" (")[0] for v in violations] == [
            f"{tmp_path.as_posix()}/components/Page.tsx:2",
            f"{tmp_path.as_posix()}/components/Page.tsx:3",
            f"{tmp_path.as_posix()}/components/Page.tsx:4",
            f"{tmp_path.as_posix()}/components/Page.tsx:5",
            f"{tmp_path.as_posix()}/pages/Raw.astro:1",
        ]

    def test_the_single_allowed_sink_is_still_there_and_goes_through_the_escaper(self):
        """A rotted allow-list would silently re-open the door it guards."""
        viewer = _read(WEB_SRC / RESPONSE_VIEWER)
        allowed = [
            line
            for line in viewer.splitlines()
            if DANGEROUS_PROP in line and SAFE_SINK_CALL in line
        ]
        assert len(allowed) == 1, (
            "el cuerpo JSON del Repeater es el único sumidero de HTML permitido "
            f"(una línea con `{DANGEROUS_PROP}` y `{SAFE_SINK_CALL}`); hay "
            f"{len(allowed)}: {allowed}"
        )
        assert 'from "@/utils/escape"' in viewer, (
            "el sumidero permitido tiene que usar el escapador compartido de "
            "`@/utils/escape`"
        )


class TestEscapeHelper:
    def test_escape_html_is_defined_exactly_once(self):
        definitions = [
            _display(path)
            for path in _iter_web_files()
            if ESCAPE_FUNCTION.search(_read(path))
        ]
        assert definitions == [_display(ESCAPE_TS)], (
            "hay una sola función de escape en apps/web/src y vive en "
            f"{_display(ESCAPE_TS)}; definiciones encontradas: {definitions}"
        )

    def test_it_escapes_the_characters_that_matter(self):
        source = _read(ESCAPE_TS)
        table = source[source.index("HTML_ESCAPES") : source.index("};", source.index("HTML_ESCAPES"))]
        assert all(char in table for char in ("&", "<", ">", '"', "'")), (
            "el escapador tiene que cubrir & < > \" ' (las dos últimas permiten "
            f"usarlo también dentro de un atributo). Tabla leída: {table!r}"
        )

    def test_highlight_body_escapes_before_it_writes_markup(self):
        source = _read(ESCAPE_TS)
        body = source[source.index("export function highlightBody") :]
        escape_at = body.index("escapeHtml(")
        markup_at = body.index("<span")
        assert escape_at < markup_at, (
            "en `highlightBody` el escape va PRIMERO y el marcado después: el "
            "cuerpo llega como texto y solo el envoltorio fijo es markup "
            f"(escape en {escape_at}, `<span` en {markup_at})"
        )
        assert "innerHTML" not in body and DANGEROUS_PROP not in body, (
            "`highlightBody` devuelve una cadena; no toca el DOM"
        )


def _node() -> str | None:
    return shutil.which("node")


def _node_runs_typescript(node: str, tmp_path: Path) -> bool:
    """Node >= 22.6 strips types on import; older ones need a build step."""
    module = tmp_path / "capability.ts"
    module.write_text("export const value: number = 1;\n", encoding="utf-8")
    runner = tmp_path / "capability.mjs"
    runner.write_text(
        f"import {{ value }} from {json.dumps(module.as_uri())};\nconsole.log(value);\n",
        encoding="utf-8",
    )
    try:
        result = subprocess.run(
            [node, str(runner)], capture_output=True, text=True, timeout=120
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and result.stdout.strip() == "1"


class TestDangerousPayloadsAreInert:
    """The escaper itself, executed: payloads must come out as text.

    Runs the real ``utils/escape.ts`` through Node's type stripping, so this is
    the only proof that says what the function *returns* instead of what it
    looks like. Runners whose Node cannot import TypeScript skip it; the static
    guards above (order, sinks, iframes) are the ones that always run.
    """

    def test_payloads_become_text_and_never_markup(self, tmp_path):
        node = _node()
        if node is None:
            pytest.skip("node is not installed; the static guards still apply")
        if not _node_runs_typescript(node, tmp_path):
            pytest.skip("this node cannot import TypeScript without a build step")

        runner = tmp_path / "probe.mjs"
        runner.write_text(
            f"import {{ highlightBody }} from {json.dumps(ESCAPE_TS.as_uri())};\n"
            "const script = JSON.stringify({x: '<script>alert(1)</script>'});\n"
            "const image = '<img src=x onerror=\"alert(localStorage.pwnproxy)\">';\n"
            "console.log(JSON.stringify({\n"
            "  json: highlightBody(script, 'application/json'),\n"
            "  html: highlightBody(image, 'text/html'),\n"
            "}));\n",
            encoding="utf-8",
        )
        result = subprocess.run([node, str(runner)], capture_output=True, text=True, timeout=120)
        assert result.returncode == 0, f"node falló: {result.stderr.strip()[:400]}"

        assert json.loads(result.stdout) == {
            "json": (
                '{<span class="text-sky-400">&quot;x&quot;</span>:'
                "&quot;&lt;script&gt;alert(1)&lt;/script&gt;&quot;}"
            ),
            "html": '&lt;img src=x onerror=&quot;alert(localStorage.pwnproxy)&quot;&gt;',
        }, "un cuerpo del objetivo salió como markup: el escape corre después del marcado"


class TestGuardIsNotVacuous:
    def test_the_scan_covers_the_real_tree(self):
        files = _iter_web_files()
        assert len(files) >= 60, f"la guarda solo recorrió {len(files)} archivos"
        assert WEB_SRC / RESPONSE_VIEWER in files
        assert WEB_SRC / "pages" / "scope" / "index.astro" in files
        assert WEB_SRC / "pages" / "reports" / "index.astro" in files
        assert WEB_SRC / "pages" / "interceptor" / "index.astro" in files

    def test_the_rendered_pages_and_islands_are_where_the_rules_look(self):
        """An iframe or a sink in a file the scan never opens would be invisible."""
        assert _iframe_tags(), "no se encontró ningún <iframe: ¿se movió el visor de respuestas?"
        viewers = {_display(path) for path, _, _ in _iframe_tags()}
        assert viewers == {_display(WEB_SRC / RESPONSE_VIEWER), _display(WEB_SRC / "components" / "intruder" / "IntruderPage.tsx")}
