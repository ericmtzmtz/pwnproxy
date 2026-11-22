"""Layering guard: ``pwnproxy.shared`` must never depend on ``pwnproxy.plugins``.

The dependency direction is ``plugins -> shared``, never the other way around
(see ``docs/plugin-architecture.md``). This module enforces the rule with an AST
walk over every ``.py`` file under ``pwnproxy/shared/`` so that imports hidden
inside functions, ``if TYPE_CHECKING:`` blocks or ``try/except`` are caught too.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SHARED_ROOT = REPO_ROOT / "pwnproxy" / "shared"
FORBIDDEN_PREFIX = "pwnproxy.plugins"


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
