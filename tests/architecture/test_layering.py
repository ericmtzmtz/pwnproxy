"""Layering guards over ``pwnproxy/``.

Two rules, both enforced with an AST walk (so imports hidden inside functions,
``if TYPE_CHECKING:`` blocks or ``try/except`` are caught too):

1. ``pwnproxy.shared`` must never depend on ``pwnproxy.plugins`` — the direction
   is ``plugins -> shared`` (see ``docs/plugin-architecture.md``).
2. Nothing under ``pwnproxy/`` may import ``apps.`` — ``apps/`` is a consumer of
   the core, never a dependency. The two exceptions that exist today are
   declared with their reason, and an obsolete entry fails the test.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SHARED_ROOT = REPO_ROOT / "pwnproxy" / "shared"
CORE_ROOT = REPO_ROOT / "pwnproxy"
FORBIDDEN_PREFIX = "pwnproxy.plugins"
APPS_PREFIX = "apps"

#: ``(relative file, imported module) -> reason`` for the only two places where
#: the core still reaches into ``apps/``. Both are scheduled to disappear with
#: the follow-up change (``tasks.md`` 10.3); adding an entry here is a conscious
#: decision, not a way to make the guard green.
DECLARED_APPS_IMPORTS: dict[tuple[str, str], str] = {
    (
        "pwnproxy/transport/rest/plugins.py",
        "apps.terminal.cli.import_cmd",
    ): "``_parse_burp_scope`` still lives under apps/ (task 10.3 moves it out)",
    (
        "pwnproxy/services/proxy/interceptor/tui/screen.py",
        "apps.terminal.tui.interceptor_widget",
    ): "the proxy interceptor screen composes a TUI widget that still lives under apps/",
}


def _module_name(path: Path) -> str:
    """Return the dotted module name of a file inside the repo."""
    relative = path.relative_to(REPO_ROOT).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _resolve_relative(path: Path, level: int, module: str | None) -> str:
    """Resolve a relative import (``from ..x import y``) to an absolute name."""
    package = _module_name(path).split(".")
    if path.name != "__init__.py":
        package = package[:-1]
    # level == 1 means "current package", so drop (level - 1) trailing components.
    base = package[: len(package) - (level - 1)] if level > 1 else package
    return ".".join([*base, module] if module else base)


def _forbidden_imports(path: Path) -> list[tuple[int, str]]:
    """Return ``(lineno, imported_module)`` for every forbidden import in ``path``."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == FORBIDDEN_PREFIX or alias.name.startswith(FORBIDDEN_PREFIX + "."):
                    hits.append((node.lineno, alias.name))
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                module = _resolve_relative(path, node.level, node.module)
            if module == FORBIDDEN_PREFIX or module.startswith(FORBIDDEN_PREFIX + "."):
                hits.append((node.lineno, module))
    return hits


def _scan_shared() -> list[str]:
    """Collect ``archivo:línea`` for every plugin import found under shared/."""
    violations: list[str] = []
    for path in sorted(SHARED_ROOT.rglob("*.py")):
        for lineno, module in _forbidden_imports(path):
            relative = path.relative_to(REPO_ROOT).as_posix()
            violations.append(f"{relative}:{lineno} (importa {module})")
    return violations


def _apps_imports(path: Path) -> list[tuple[int, str]]:
    """Return ``(lineno, module)`` for every ``apps.`` import in ``path``."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == APPS_PREFIX or alias.name.startswith(APPS_PREFIX + "."):
                    hits.append((node.lineno, alias.name))
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                module = _resolve_relative(path, node.level, node.module)
            if module == APPS_PREFIX or module.startswith(APPS_PREFIX + "."):
                hits.append((node.lineno, module))
    return hits


def _display_path(path: Path, base: Path) -> str:
    """Return ``path`` relative to the repo when possible, else to ``base``."""
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.relative_to(base).as_posix()


def _scan_core_for_apps(root: Path | None = None) -> list[tuple[str, int, str]]:
    """Collect every ``pwnproxy/`` module that imports ``apps.``.

    Args:
        root: Directory to scan; defaults to ``pwnproxy/``. Tests point it at a
            temporary tree.

    Returns:
        ``(relative path, lineno, imported module)`` per violation.
    """
    base = root if root is not None else CORE_ROOT
    violations: list[tuple[str, int, str]] = []
    for path in sorted(base.rglob("*.py")):
        for lineno, module in _apps_imports(path):
            violations.append((_display_path(path, base), lineno, module))
    return violations


class TestSharedDoesNotImportPlugins:
    def test_no_plugin_imports_under_shared(self):
        violations = _scan_shared()
        assert violations == [], (
            "pwnproxy/shared/ no puede importar pwnproxy.plugins "
            "(la dependencia va de plugins -> shared):\n" + "\n".join(violations)
        )

    def test_guard_detects_nested_import(self, tmp_path):
        """The AST walk must catch imports inside functions and TYPE_CHECKING blocks."""
        sample = tmp_path / "sample.py"
        sample.write_text(
            "from __future__ import annotations\n"
            "import typing\n"
            "if typing.TYPE_CHECKING:\n"
            "    from pwnproxy.plugins.core.base import Finding\n"
            "def f():\n"
            "    import pwnproxy.plugins.core.chain\n"
            "    return None\n",
            encoding="utf-8",
        )
        assert [lineno for lineno, _ in _forbidden_imports(sample)] == [4, 6]

    def test_guard_ignores_unrelated_imports(self, tmp_path):
        sample = tmp_path / "sample.py"
        sample.write_text(
            "import pwnproxy.shared.models\n"
            "from pwnproxy.shared.scan import params\n"
            "from pwnproxy.sharedplugins import thing\n",
            encoding="utf-8",
        )
        assert _forbidden_imports(sample) == []


class TestCoreDoesNotImportApps:
    """``pwnproxy/`` is the library; ``apps/`` is one of its clients."""

    def test_only_the_declared_exceptions_reach_into_apps(self):
        found = {(relative, module) for relative, _, module in _scan_core_for_apps()}

        assert found == set(DECLARED_APPS_IMPORTS), (
            "pwnproxy/ no puede importar apps/ (apps/ es un consumidor del núcleo).\n"
            f"sin declarar: {sorted(found - set(DECLARED_APPS_IMPORTS))}\n"
            f"excepciones obsoletas (ya no existen, bórralas): "
            f"{sorted(set(DECLARED_APPS_IMPORTS) - found)}"
        )

    def test_the_guard_catches_a_nested_import(self, tmp_path):
        """The AST walk sees imports inside functions, not only module level."""
        (tmp_path / "module.py").write_text(
            "def handler():\n"
            "    from apps.terminal.cli.import_cmd import _parse_burp_scope\n"
            "    return _parse_burp_scope\n",
            encoding="utf-8",
        )

        assert [(relative, lineno, module) for relative, lineno, module in _scan_core_for_apps(tmp_path)] == [
            ("module.py", 2, "apps.terminal.cli.import_cmd")
        ]

    def test_the_guard_ignores_unrelated_imports(self, tmp_path):
        (tmp_path / "module.py").write_text(
            "import apps_helpers\n"
            "from pwnproxy.shared import models\n"
            "from appsx.terminal import thing\n",
            encoding="utf-8",
        )

        assert _scan_core_for_apps(tmp_path) == []

    def test_an_obsolete_exception_fails(self, tmp_path):
        """A declared entry that no longer exists must break the guard."""
        declared = {("transport/rest/plugins.py", "apps.terminal.cli.import_cmd")}
        target = tmp_path / "transport" / "rest"
        target.mkdir(parents=True)
        (target / "plugins.py").write_text(
            "def scope():\n    from apps.terminal.cli.import_cmd import _parse_burp_scope\n",
            encoding="utf-8",
        )
        present = {(relative, module) for relative, _, module in _scan_core_for_apps(tmp_path)}

        # While the import exists the declared entry matches (guard green)...
        assert (present, declared - present) == (declared, set())

        # ...once it disappears the same comparison reports the stale entry.
        (target / "plugins.py").write_text("def scope():\n    return None\n", encoding="utf-8")
        gone = {(relative, module) for relative, _, module in _scan_core_for_apps(tmp_path)}

        assert (gone - declared, declared - gone) == (
            set(),
            {("transport/rest/plugins.py", "apps.terminal.cli.import_cmd")},
        )


class TestPluginReExports:
    """Moved base types stay importable from their historical plugin modules."""

    def test_finding_is_the_same_object(self):
        from pwnproxy.plugins.core.base import Finding as plugin_finding
        from pwnproxy.shared.scan.finding import Finding as shared_finding

        assert plugin_finding is shared_finding

    def test_chain_types_are_the_same_objects(self):
        from pwnproxy.plugins.core.chain import (
            DetectionDepth as plugin_depth,
        )
        from pwnproxy.plugins.core.chain import (
            DetectionStage as plugin_stage,
        )
        from pwnproxy.plugins.core.chain import (
            StageResult as plugin_result,
        )
        from pwnproxy.shared.scan.stage import (
            DetectionDepth as shared_depth,
        )
        from pwnproxy.shared.scan.stage import (
            DetectionStage as shared_stage,
        )
        from pwnproxy.shared.scan.stage import (
            StageResult as shared_result,
        )

        assert (plugin_depth, plugin_stage, plugin_result) == (shared_depth, shared_stage, shared_result)
