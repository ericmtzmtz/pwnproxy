import importlib.util
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from apps.terminal.cli import plugin as plugin_cli

runner = CliRunner()


@pytest.mark.parametrize("tmpl", ["scanner", "crawler", "exploiter", "hook"])
def test_template_generates_valid_code(tmp_path: Path, tmpl: str):
    """Verify each template produces syntactically valid Python with the expected class."""
    name = "mytest"
    result = runner.invoke(
        plugin_cli.app,
        ["create", name, "--template", tmpl, "--dir", str(tmp_path)],
    )
    assert result.exit_code == 0, f"CLI failed: {result.output}"

    pkg_dir = tmp_path / f"pwnproxy-{tmpl}-{name}"
    assert pkg_dir.is_dir(), f"Directory not created: {pkg_dir}"
    plugin_file = pkg_dir / "plugin.py"
    assert plugin_file.is_file(), "plugin.py not created"

    source = plugin_file.read_text(encoding="utf-8")
    compile(source, str(plugin_file), "exec")

    spec = importlib.util.spec_from_file_location(f"test_{tmpl}_plugin", plugin_file)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)

    expected_class = f"{name}Plugin"
    assert hasattr(mod, expected_class), f"{expected_class} not found"


def test_unknown_template_fails(tmp_path: Path):
    """Unknown template type should exit with error."""
    result = runner.invoke(
        plugin_cli.app,
        ["create", "test", "--template", "invalid", "--dir", str(tmp_path)],
    )
    assert result.exit_code != 0


def test_duplicate_directory_fails(tmp_path: Path):
    """Creating a plugin in an existing directory should fail."""
    result = runner.invoke(
        plugin_cli.app,
        ["create", "dup", "--template", "scanner", "--dir", str(tmp_path)],
    )
    assert result.exit_code == 0

    result = runner.invoke(
        plugin_cli.app,
        ["create", "dup", "--template", "scanner", "--dir", str(tmp_path)],
    )
    assert result.exit_code != 0
    assert "already exists" in result.output
