"""Guard: the plugin configuration UI is built from the schema, not from names.

The Web UI section that configures a plugin
(``apps/web/src/components/plugins/config/`` and
``apps/web/src/api/plugins/config/``) paints the whole form from
``GET /api/v1/plugins/{name}/schema``: settings, collections and actions. The
moment one plugin name or one hardcoded list of configuration keys appears
there, the UI has a registry again — a plugin nobody wrote code for would not
show up, and a field renamed by the plugin would leave a stale form behind.

Two textual rules, because the tree is TypeScript and an AST walk is not
available from this suite (the same reason ``test_web_api_client.py`` is
textual):

1. **No plugin name** (``TestNoPluginNames``): a quoted catalog name — the six
   built-ins plus the example plugin of ``openspec/changes/plugin-config-api``,
   which is the shape a "special case" would take.
2. **No key registry** (``TestNoHardcodedKeys``): a literal array with two or
   more quoted single-token strings. The contract's vocabulary is a TypeScript
   union type, never a list, so such an array is either a list of plugin fields
   or the start of one.

A hit is reported as ``archivo:línea (línea)``. The whitelist is empty on
purpose: a plugin name in this subtree is the defect the guard exists for.
"""

from __future__ import annotations

import re
from pathlib import Path

#: Repository root (``tests/architecture/<this file>``).
REPO_ROOT = Path(__file__).resolve().parents[2]

#: Web UI sources.
WEB_SRC = REPO_ROOT / "apps" / "web" / "src"

#: The two subtrees this guard owns, relative to ``WEB_SRC``.
CONFIG_DIRS = (
    Path("components") / "plugins" / "config",
    Path("api") / "plugins" / "config",
)

#: Catalog names a client must never branch on, plus the design's example one.
PLUGIN_NAMES = (
    "sqli",
    "xss",
    "lfi",
    "xxe",
    "ssrf",
    "command-injection",
    "command_injection",
    "example-checker",
)

#: Files that can hold a form; assets cannot.
SCANNED_SUFFIXES = {".ts", ".tsx"}

#: A catalog name as a string literal (``"xss"``, ``'xss'``, ``\`xss\`\`).
QUOTED_NAME = re.compile(
    r"""["'`](?P<name>""" + "|".join(re.escape(name) for name in PLUGIN_NAMES) + r""")["'`]"""
)

#: A quoted single-token string, with either quote style.
_QUOTED = r"(?:\"[^\"\s]{1,40}\"|'[^'\s]{1,40}')"

#: A literal array of two or more quoted single-token strings (may span lines).
KEY_LIST = re.compile(r"\[\s*(?:" + _QUOTED + r"\s*,\s*)+" + _QUOTED + r"\s*,?\s*\]")


def _display(path: Path) -> str:
    """Repo-relative path when possible, absolute otherwise (mutation trees)."""
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _config_files(web_src: Path = WEB_SRC) -> list[Path]:
    """Every source file of the two configuration subtrees, sorted."""
    files: list[Path] = []
    for relative in CONFIG_DIRS:
        folder = web_src / relative
        if not folder.is_dir():
            continue
        files.extend(
            path
            for path in sorted(folder.rglob("*"))
            if path.is_file() and path.suffix.lower() in SCANNED_SUFFIXES
        )
    return files


def _hits(path: Path, pattern: re.Pattern[str]) -> list[str]:
    """Collect ``archivo:línea (línea)`` for every match of ``pattern`` in ``path``."""
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []
    lines = text.splitlines()
    hits: list[str] = []
    for match in pattern.finditer(text):
        lineno = text.count("\n", 0, match.start()) + 1
        preview = lines[lineno - 1].strip() if lineno <= len(lines) else match.group(0)
        hits.append(f"{_display(path)}:{lineno} ({preview})")
    return hits


def _scan(pattern: re.Pattern[str], web_src: Path = WEB_SRC) -> list[str]:
    """Run one rule over the configuration subtrees of ``web_src``."""
    violations: list[str] = []
    for path in _config_files(web_src):
        violations.extend(_hits(path, pattern))
    return violations


class TestNoPluginNames:
    def test_no_plugin_name_in_the_configuration_ui(self):
        violations = _scan(QUOTED_NAME)
        assert violations == [], (
            "la configuración de un plugin se pinta solo desde GET …/schema: un nombre "
            "del catálogo en este subtree es un caso especial que el resto de plugins "
            "no tendría. Offenders:\n" + "\n".join(violations)
        )

    def test_guard_detects_a_plugin_name(self, tmp_path):
        """The rule must fail on the shape it exists to forbid."""
        folder = tmp_path / CONFIG_DIRS[0]
        folder.mkdir(parents=True)
        (folder / "Panel.tsx").write_text(
            "const first = <Panel plugin=\"xss\" />;\n"
            'const special = "example-checker";\n',
            encoding="utf-8",
        )
        violations = _scan(QUOTED_NAME, web_src=tmp_path)
        assert [hit.split(" (")[0] for hit in violations] == [
            f"{_display(folder / 'Panel.tsx')}:1",
            f"{_display(folder / 'Panel.tsx')}:2",
        ]


class TestNoHardcodedKeys:
    def test_no_hardcoded_key_registry(self):
        violations = _scan(KEY_LIST)
        assert violations == [], (
            "las claves salen del esquema (FieldSpec.key); una lista literal es un "
            "registro paralelo que se queda viejo en cuanto el plugin declara otra "
            "clave. Offenders:\n" + "\n".join(violations)
        )

    def test_guard_detects_a_key_list(self, tmp_path):
        folder = tmp_path / CONFIG_DIRS[0]
        folder.mkdir(parents=True)
        (folder / "Form.tsx").write_text(
            'const KEYS = ["signing_key", "auth_header"];\n'
            "const OTHER = [\n  'name',\n  'events',\n];\n",
            encoding="utf-8",
        )
        violations = _scan(KEY_LIST, web_src=tmp_path)
        assert [hit.split(" (")[0] for hit in violations] == [
            f"{_display(folder / 'Form.tsx')}:1",
            f"{_display(folder / 'Form.tsx')}:2",
        ]

    def test_a_single_key_or_an_object_is_not_a_registry(self, tmp_path):
        folder = tmp_path / CONFIG_DIRS[0]
        folder.mkdir(parents=True)
        (folder / "One.tsx").write_text(
            'const ONE = "signing_key";\n'
            'const LIST = ["signing_key"];\n'
            'const MAP = { signing_key: "Signing key" };\n',
            encoding="utf-8",
        )
        assert _scan(KEY_LIST, web_src=tmp_path) == []


class TestGuardIsNotVacuous:
    def test_the_scan_covers_the_real_tree(self):
        files = _config_files()
        relative = {path.relative_to(WEB_SRC).as_posix() for path in files}
        assert "components/plugins/config/PluginConfigPanel.tsx" in relative, (
            "la guarda no encontró el panel: ¿se movió el subtree?"
        )
        assert "api/plugins/config/calls.ts" in relative, (
            "la guarda no encontró las llamadas: ¿se movió el subtree?"
        )
        assert len(files) >= 8, f"la guarda solo recorrió {len(files)} archivos"

    def test_the_form_comes_from_the_schema(self):
        panel = (WEB_SRC / CONFIG_DIRS[0] / "PluginConfigPanel.tsx").read_text(encoding="utf-8")
        assert "getPluginSchema" in panel, (
            "el panel tiene que pedir el esquema: la forma viene del servidor"
        )
        for collection in ("settings", "collections", "actions"):
            assert f"schema.{collection}" in panel, (
                f"el panel ya no pinta `{collection}` del esquema"
            )
