"""Pytest options for the performance baseline test (tests/perf/).

Adds two mutually-exclusive opt-in flags:
  --perf-record   run the perf crawl and write tests/perf/baseline.json
  --perf-check    run the perf crawl and compare against baseline.json
                  with a x3 tolerance (regression detector, not a benchmark)

Without either flag the perf test is skipped (never runs in normal CI).
"""

import os
import tempfile
import uuid
from types import SimpleNamespace
from unittest import mock

import pytest


@pytest.fixture(scope="session", autouse=True)
def isolated_pwnproxy_config_dir():
    """Keep the plugin activation config out of the user's real ``~/.pwnproxy``.

    ``[plugin.activation]`` decides what the plugin loader loads, so a test that
    discovered plugins would otherwise depend on (and be able to modify) the
    developer's own ``config.toml``. The whole session points
    ``PWNPROXY_CONFIG_DIR`` at an empty temporary directory; a test that needs a
    specific file patches the variable itself.
    """
    with tempfile.TemporaryDirectory(prefix="pwnproxy-config-") as config_dir:
        with mock.patch.dict(os.environ, {"PWNPROXY_CONFIG_DIR": config_dir}):
            yield config_dir


@pytest.fixture
def install_fake_plugin(tmp_path, monkeypatch):
    """Return a factory that installs a fake plugin distribution for one test.

    There is no ``pip install`` involved (the suite must not touch the venv): a
    distribution is a module file plus a ``*.dist-info`` directory with an
    ``entry_points.txt``, and both go on ``sys.path`` for the duration of the
    test — exactly what ``importlib.metadata`` reads. ``monkeypatch`` undoes the
    ``sys.path`` entry at teardown.

    The factory returns a ``SimpleNamespace`` with the module name, the plugin
    name, the package/version and the paths, so a test can import the module to
    inspect it.
    """

    def install(
        *,
        dist: str = "pwnproxy-pro",
        version: str = "1.2.0",
        plugin_name: str = "authorization-matrix",
        plugin_version: str = "2.0.0",
        class_name: str = "FakeScanner",
        group: str = "pwnproxy.plugins",
        entry_name: str | None = None,
        target: str | None = None,
        source: str | None = None,
        extra: str = "",
    ) -> SimpleNamespace:
        module = f"fake_pwnproxy_plugin_{uuid.uuid4().hex[:10]}"
        if source is None:
            source = (
                "from pwnproxy.plugins.core.base import PluginMetadata, ScannerPlugin\n"
                "\n"
                f"class {class_name}(ScannerPlugin):\n"
                "    metadata = PluginMetadata(\n"
                f"        name={plugin_name!r},\n"
                f"        version={plugin_version!r},\n"
                "        author='fixture',\n"
                "        consumes=['flow'],\n"
                "        produces=['finding'],\n"
                "    )\n"
                "\n"
                "    async def on_flow(self, flow):\n"
                "        if False:\n"
                "            yield None\n"
                f"{extra}"
            )
        module_path = tmp_path / f"{module}.py"
        module_path.write_text(source, encoding="utf-8")

        dist_info = tmp_path / f"{dist.replace('-', '_')}-{version}.dist-info"
        dist_info.mkdir()
        (dist_info / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {dist}\nVersion: {version}\n", encoding="utf-8"
        )
        (dist_info / "entry_points.txt").write_text(
            f"[{group}]\n{entry_name or plugin_name} = {target or f'{module}:{class_name}'}\n",
            encoding="utf-8",
        )
        monkeypatch.syspath_prepend(str(tmp_path))
        return SimpleNamespace(
            module=module,
            plugin_name=plugin_name,
            package=dist,
            version=plugin_version,
            package_version=version,
            module_path=module_path,
            dist_info=dist_info,
        )

    return install


@pytest.fixture
def activation_config(tmp_path, monkeypatch):
    """Point ``[plugin.activation]`` at a temp ``config.toml`` and return its path.

    The returned callable writes the file with the given table body, so tests
    never read or write ``~/.pwnproxy/config.toml``.
    """
    monkeypatch.setenv("PWNPROXY_CONFIG_DIR", str(tmp_path))

    def write(body: str) -> "os.PathLike[str]":
        path = tmp_path / "config.toml"
        path.write_text(body, encoding="utf-8")
        return path

    return write


def pytest_addoption(parser):
    group = parser.getgroup("perf")
    group.addoption(
        "--perf-record",
        action="store_true",
        default=False,
        help="Record crawl duration/max_rss into tests/perf/baseline.json",
    )
    group.addoption(
        "--perf-check",
        action="store_true",
        default=False,
        help="Compare crawl duration/max_rss against tests/perf/baseline.json (x3 tolerance)",
    )


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Report tests marked @pytest.mark.flaky that ran.

    Flaky tests are NOT deselected (see the CI policy: mark → root-cause →
    fix → unmark). This summary makes them visible so a known-intermittent
    test cannot be silently "green" forever.
    """
    flaky_runs = [
        rep
        for rep in terminalreporter.stats.get("passed", [])
        if "flaky" in rep.keywords or (rep.nodeid and "flaky" in str(rep.keywords))
    ]
    flaky_fail = [
        rep
        for rep in terminalreporter.stats.get("failed", [])
        if "flaky" in rep.keywords
    ]
    if flaky_runs or flaky_fail:
        terminalreporter.write_sep("-", "flaky marker report", green=True)
        if flaky_runs:
            terminalreporter.write_line(f"  flaky tests passed : {len(flaky_runs)}")
        if flaky_fail:
            terminalreporter.write_line(
                f"  flaky tests FAILED  : {len(flaky_fail)} — root-cause required before unmarking"
            )
