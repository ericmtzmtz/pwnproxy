"""Guard: no module keeps its own list of scanner names.

The change removed four registries (CLI ``scan``, CLI ``findings``, TUI scanner
widget, ``transport/rest/scanners``) that each had a literal list of scanner
names next to the catalog. A hardcoded list is not a style nit: it is a registry
that hides every installed plugin and drifts from the built-ins, which is exactly
how a plugin "disappeared" before this change.

The rule, enforced with an AST walk over ``pwnproxy/`` and ``apps/``: no
``list``/``set``/``tuple`` literal may contain two or more scanner names — that
is the shape of a registry. A single name is allowed (a plugin, a docstring, a
test of one scanner) and so is a ``dict`` (the catalog's ``command_injection ->
command-injection`` alias map is legitimate); the whitelist is empty on purpose.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCANNED_ROOTS = (REPO_ROOT / "pwnproxy", REPO_ROOT / "apps")

#: Built-in scanner names. They appear here (a test) and nowhere else as a
#: literal registry; the production list comes from
#: :func:`pwnproxy.plugins.core.catalog.discover_plugins`.
SCANNER_NAMES = frozenset(
    {"sqli", "xss", "lfi", "xxe", "ssrf", "command-injection", "command_injection"}
)

#: Deliberate exceptions, ``"relative/path.py" -> reason``. Empty by design.
WHITELIST: dict[str, str] = {}


def _string_literals(node: ast.AST) -> list[str]:
    """Return the string constants directly inside a list/set/tuple literal."""
    if not isinstance(node, (ast.List, ast.Set, ast.Tuple)):
        return []
    return [
        element.value
        for element in node.elts
        if isinstance(element, ast.Constant) and isinstance(element.value, str)
    ]


def _scanner_lists(path: Path) -> list[tuple[int, list[str]]]:
    """Return ``(lineno, names)`` for every registry-shaped literal in ``path``."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    hits: list[tuple[int, list[str]]] = []
    for node in ast.walk(tree):
        names = [value for value in _string_literals(node) if value in SCANNER_NAMES]
        if len(names) >= 2:
            hits.append((node.lineno, names))
    return hits


def _scan(roots: tuple[Path, ...] = SCANNED_ROOTS) -> list[str]:
    """Collect ``archivo:línea (nombres)`` for every literal registry found."""
    violations: list[str] = []
    for root in roots:
        for path in sorted(root.rglob("*.py")):
            relative = path.relative_to(REPO_ROOT).as_posix()
            if relative in WHITELIST:
                continue
            for lineno, names in _scanner_lists(path):
                violations.append(f"{relative}:{lineno} ({names})")
    return violations


class TestNoHardcodedScannerRegistry:
    def test_no_module_keeps_its_own_scanner_list(self):
        violations = _scan()
        assert violations == [], (
            "los nombres de scanner salen de pwnproxy.plugins.core.catalog; "
            "una lista literal es un registro paralelo:\n" + "\n".join(violations)
        )

    def test_the_guard_catches_a_registry(self, tmp_path):
        (tmp_path / "registry.py").write_text(
            'SCANNERS = ["sqli", "xss", "lfi"]\n'
            'ORDER = ("lfi", "xxe")\n'
            'ENABLED = {"ssrf", "sqli"}\n',
            encoding="utf-8",
        )

        assert _scanner_lists(tmp_path / "registry.py") == [
            (1, ["sqli", "xss", "lfi"]),
            (2, ["lfi", "xxe"]),
            (3, ["ssrf", "sqli"]),
        ]

    def test_a_single_name_is_not_a_registry(self, tmp_path):
        (tmp_path / "one.py").write_text(
            'DEFAULT = "sqli"\nORDER = ["sqli"]\n',
            encoding="utf-8",
        )

        assert _scanner_lists(tmp_path / "one.py") == []

    def test_an_unrelated_list_is_ignored(self, tmp_path):
        (tmp_path / "other.py").write_text(
            'LEVELS = ["low", "medium", "high", "critical"]\n',
            encoding="utf-8",
        )

        assert _scanner_lists(tmp_path / "other.py") == []
