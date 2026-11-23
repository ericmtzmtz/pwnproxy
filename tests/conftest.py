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
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest
from fastapi.testclient import TestClient

#: Token every test authenticates with. It enters through
#: ``PWNPROXY_API_TOKEN`` (see :func:`api_token_env`) so the suite never writes a
#: token file — the session already redirects ``PWNPROXY_CONFIG_DIR`` to a
#: temporary directory, and nothing may touch the developer's ``~/.pwnproxy``.
TEST_API_TOKEN = "test-api-token-1c9f4a7be2d8460f9b3a5"

#: Subprotocols a WebSocket client must offer: the plain name the server answers
#: plus the one carrying the token.
WS_SUBPROTOCOLS = ["pwnproxy", f"pwnproxy-token.{TEST_API_TOKEN}"]

#: ``sys.path`` roots where this session installed a fake plugin distribution.
#: The autouse :func:`isolated_installed_plugins` filter only lets entry points
#: from these roots through, so the suite never sees the developer's own
#: installed plugins (``pwnproxy-pro``, a marketplace plugin, ...).
FAKE_DIST_ROOTS: set[str] = set()


class AuthenticatedTestClient(TestClient):
    """``TestClient`` that talks to the authenticated API like a real client.

    Every request carries ``Authorization: Bearer <TEST_API_TOKEN>`` and every
    ``websocket_connect`` offers :data:`WS_SUBPROTOCOLS` (unless the test passes
    its own, which the negative tests do). Tests that need to see the ``401`` or
    the ``4401`` use a plain ``TestClient`` on purpose: that is the only way to
    prove the guard exists.
    """

    def __init__(self, app, *, headers: dict[str, str] | None = None, **kwargs) -> None:
        merged = {"Authorization": f"Bearer {TEST_API_TOKEN}", **(headers or {})}
        super().__init__(app, headers=merged, **kwargs)

    def websocket_connect(self, url, subprotocols=None, **kwargs):
        return super().websocket_connect(url, subprotocols=subprotocols or WS_SUBPROTOCOLS, **kwargs)


def _installed_by_this_suite(entry_point) -> bool:
    """Return ``True`` when ``entry_point`` comes from a fake test distribution.

    The distribution's location is the directory that holds its ``.dist-info``
    (``Distribution.locate_file("")``), i.e. the ``sys.path`` entry the fixture
    prepended — ``tmp_path`` for a fake plugin, ``site-packages`` for a real one.
    """
    distribution = getattr(entry_point, "dist", None)
    locate = getattr(distribution, "locate_file", None)
    if locate is None:
        return False
    try:
        location = Path(locate("")).resolve()
    except Exception:  # a metadata backend that cannot locate its files
        return False
    return any(location == Path(root).resolve() or Path(root).resolve() in location.parents
               for root in FAKE_DIST_ROOTS)


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


@pytest.fixture(scope="session", autouse=True)
def api_token_env():
    """Export the suite token so nothing has to write a token file.

    ``PWNPROXY_API_TOKEN`` is the CI path of the contract: the server accepts it
    as a ``full`` token and never persists it. Autouse and session-scoped, so
    every ``(Authenticated)TestClient`` in every module authenticates without
    each file having to opt in.
    """
    with mock.patch.dict(os.environ, {"PWNPROXY_API_TOKEN": TEST_API_TOKEN}):
        yield TEST_API_TOKEN


@pytest.fixture(scope="session")
def test_api_token(api_token_env) -> str:
    """The suite token, for tests that build headers or subprotocols by hand."""
    return api_token_env


@pytest.fixture(scope="session")
def api_client():
    """Factory: a ``TestClient`` that sends the token (HTTP and WebSocket).

    Usage: ``with api_client(app) as client:`` — same object as ``TestClient``
    plus the credentials, so a test only changes the construction of its client.
    """
    return AuthenticatedTestClient


@pytest.fixture(scope="session", autouse=True)
def isolated_installed_plugins():
    """Make the plugin catalog see only the distributions this suite installs.

    ``discover_plugins`` reads the ``pwnproxy.plugins`` entry points of the live
    environment, so without this a developer who installed a real plugin
    (``pip install pwnproxy-pro``) would see assertions like "the catalog is only
    the built-ins" fail — the suite would depend on the machine it runs on.
    Nothing is uninstalled: the enumeration seam is patched to drop entry points
    whose distribution does not live under a directory
    :func:`install_fake_plugin` put on ``sys.path``.
    """
    from pwnproxy.plugins.core import catalog

    real_iter = catalog._iter_entry_points

    def only_test_distributions():
        return [ep for ep in real_iter() if _installed_by_this_suite(ep)]

    with mock.patch.object(catalog, "_iter_entry_points", only_test_distributions):
        yield


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
        # Register the root so the session-wide entry-point filter lets this
        # fake distribution through (see ``isolated_installed_plugins``).
        FAKE_DIST_ROOTS.add(str(tmp_path))
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
