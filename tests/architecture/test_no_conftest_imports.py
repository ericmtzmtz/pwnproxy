"""Guard: no test module imports from a ``conftest`` nor from the ``tests`` package.

Two rules, both AST-based (an import is a syntax node, and a textual pattern
would trip on the many docstrings that talk *about* this very trap):

1. **No ``conftest`` imports** (:class:`TestNoConftestImports`). A ``conftest.py``
   is loaded by pytest, not a library: importing names from it makes the test
   depend on how the runner happens to name the module.
2. **No absolute ``tests.*`` imports** (:class:`TestNoTestsPackageImports`). The
   suite must reach its helpers with a relative import, because ``tests`` is an
   ambiguous package name in this repo.

Why rule 2 is not pedantry: ``tests/`` has no ``__init__.py`` while
``apps/mcp/tests/__init__.py`` does. The moment a run collects both trees
(``pytest apps/mcp/tests tests/api/...``), pytest names the MCP directory
``tests`` — a real package — and ``from tests.api.conftest import NAME`` in
``tests/api/test_ws_plugin_config.py`` died with
``ModuleNotFoundError: No module named 'tests.api'``. The three tests of the
plugin-configuration section were the only ones broken, but the whole run was
interrupted at collection. Fakes that several tests share now live in a plain
module (``tests/api/_plugin_config_fakes.py``) and are imported relatively.

A violation is reported as ``archivo:línea (texto de la línea)``. Proven red by
re-adding ``from tests.api.conftest import NAME`` to
``tests/api/test_ws_plugin_config.py`` (restored): both rules fired on that one
line — see ``docs/sesiones/plataforma.md``.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

#: Trees the guards inspect: the suite and the per-app suites.
ROOTS = (REPO_ROOT / "tests", *(REPO_ROOT / "apps").glob("*/tests"))

#: Directories that never hold hand-written imports.
PRUNED_DIR_NAMES = {"__pycache__", ".venv", "node_modules"}


def _iter_test_files() -> list[Path]:
    """Every ``.py`` under the guarded trees, sorted for a stable message."""
    files: list[Path] = []
    for root in ROOTS:
        if not root.is_dir():
            continue
        for path in root.rglob("*.py"):
            if not path.is_file():
                continue
            if any(part in PRUNED_DIR_NAMES for part in path.parts):
                continue
            files.append(path)
    return sorted(files)


def _display(path: Path) -> str:
    """Repo-relative path when possible, absolute otherwise."""
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _imports_of_conftest(tree: ast.AST) -> list[ast.stmt]:
    """Import statements that pull something out of a ``conftest`` module."""
    found: list[ast.stmt] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            parts = node.module.split(".") if node.module else []
            imports_conftest = "conftest" in parts or (
                not parts and any(alias.name == "conftest" for alias in node.names)
            )
            if imports_conftest:
                found.append(node)
        elif isinstance(node, ast.Import):
            if any(alias.name.split(".")[-1] == "conftest" for alias in node.names):
                found.append(node)
    return found


def _imports_of_tests_package(tree: ast.AST) -> list[ast.stmt]:
    """**Absolute** imports rooted at the ambiguous ``tests`` package name."""
    found: list[ast.stmt] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level:
                continue
            if node.module and node.module.split(".")[0] == "tests":
                found.append(node)
        elif isinstance(node, ast.Import):
            if any(alias.name.split(".")[0] == "tests" for alias in node.names):
                found.append(node)
    return found


def _report(path: Path, nodes: list[ast.stmt], lines: list[str]) -> list[str]:
    """``archivo:línea (texto)`` for every offending statement."""
    return [
        f"{_display(path)}:{node.lineno} ({lines[node.lineno - 1].strip()})" for node in nodes
    ]


def _violations(collector) -> list[str]:
    """Every offending line in the guarded trees, as readable strings."""
    found: list[str] = []
    for path in _iter_test_files():
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text, filename=str(path))
        nodes = collector(tree)
        if nodes:
            found.extend(_report(path, nodes, text.splitlines()))
    return found


class TestNoConftestImports:
    """A test that imports from ``conftest`` is tied to the runner's module naming."""

    def test_no_test_module_imports_from_a_conftest(self):
        """Shared helpers go to a plain module, imported relatively."""
        violations = _violations(_imports_of_conftest)

        assert not violations, (
            "no file may import from a `conftest` module: pytest loads it, it is not a "
            "library. Move the shared names to a plain module next to the tests and "
            "import them relatively (`from ._fakes import NAME`).\n" + "\n".join(violations)
        )


class TestNoTestsPackageImports:
    """``tests`` resolves to ``apps/mcp/tests`` whenever that tree is collected too."""

    def test_no_test_module_imports_the_tests_package_absolutely(self):
        """Relative imports only: the name ``tests`` is ambiguous in this repo."""
        violations = _violations(_imports_of_tests_package)

        assert not violations, (
            "no file may import from the absolute `tests` package: when a run also "
            "collects `apps/mcp/tests` (which has an `__init__.py`) the name `tests` "
            "binds to that package and collection dies with ModuleNotFoundError. "
            "Use a relative import (`from ._fakes import NAME`).\n" + "\n".join(violations)
        )


def test_the_guarded_trees_are_not_empty():
    """A moved directory would leave both guards silently green."""
    files = _iter_test_files()

    assert len(files) > 20, f"only {len(files)} test files found under {[str(r) for r in ROOTS]}"
    assert any(path.name == "conftest.py" for path in files), (
        "no conftest.py found: the guarded roots no longer point at the suite"
    )


@pytest.mark.parametrize(
    ("source", "conftest", "tests_package"),
    [
        ("from tests.api.conftest import NAME\n", True, True),
        ("from conftest import NAME\n", True, False),
        ("from .conftest import NAME\n", True, False),
        ("from ..conftest import NAME\n", True, False),
        ("from . import conftest\n", True, False),
        ("import tests.api.conftest\n", True, True),
        ("import tests.api.fakes\n", False, True),
        ("from tests.api._fakes import NAME\n", False, True),
        ("from ._fakes import NAME\n", False, False),
        ("from pwnproxy.shared.api_token import write_token\n", False, False),
    ],
    ids=[
        "tests.api.conftest",
        "conftest",
        "relative-conftest",
        "parent-relative-conftest",
        "relative-name-conftest",
        "import-tests-conftest",
        "import-tests-fakes",
        "from-tests-fakes",
        "relative-fakes",
        "library-import",
    ],
)
def test_the_detectors_see_what_they_claim(source: str, conftest: bool, tests_package: bool):
    """The two collectors, against the spellings a future edit could use."""
    tree = ast.parse(source)

    assert bool(_imports_of_conftest(tree)) is conftest
    assert bool(_imports_of_tests_package(tree)) is tests_package
