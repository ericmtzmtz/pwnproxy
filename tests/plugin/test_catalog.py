"""Catalog tests: one discovery function for built-ins and installed plugins.

Every case here is about the contract of ``discover_plugins``:

* built-ins come from the tree, installed plugins from the ``pwnproxy.plugins``
  entry-point group only (a ``pwnproxy-*`` package without an entry point is
  invisible, which is the whole point of not guessing by name);
* a broken package is an entry with ``error``, never an exception that hides the
  rest;
* a name collision keeps the built-in and reports the installed one.

The "installed" side uses a real distribution: a module plus a ``*.dist-info``
directory on ``sys.path`` (no ``pip install``), so ``importlib.metadata`` — the
production path — is what resolves the entry point.
"""

import importlib

from pwnproxy.plugins.core.catalog import (
    ENTRY_POINT_GROUP,
    SOURCE_BUILTIN,
    SOURCE_INSTALLED,
    discover_plugins,
)

#: Built-in scanners shipped in ``pwnproxy/plugins/scanners``. Asserting the exact
#: set on purpose: adding or losing one must be a deliberate change.
BUILTIN_NAMES = ["command-injection", "lfi", "sqli", "ssrf", "xss", "xxe"]


def _plugin_source(class_name: str, plugin_name: str, version: str = "1.0.0") -> str:
    """Return the source of a minimal built-in plugin module."""
    return (
        "from pwnproxy.plugins.core.base import PluginMetadata, ScannerPlugin\n"
        "\n"
        f"class {class_name}(ScannerPlugin):\n"
        "    metadata = PluginMetadata(\n"
        f"        name={plugin_name!r},\n"
        f"        version={version!r},\n"
        "        consumes=['flow'],\n"
        "        produces=['finding'],\n"
        "    )\n"
        "\n"
        "    async def on_flow(self, flow):\n"
        "        if False:\n"
        "            yield None\n"
    )


class TestBuiltinDiscovery:
    def test_builtins_are_listed_with_source_and_package(self):
        records = discover_plugins()

        assert [(r.name, r.source, r.package) for r in records] == [
            (name, SOURCE_BUILTIN, "pwnproxy") for name in BUILTIN_NAMES
        ]
        assert [r.error for r in records] == [None] * len(BUILTIN_NAMES)
        assert all(callable(r.factory) for r in records)

    def test_metadata_version_and_category_come_from_the_plugin(self):
        records = {record.name: record for record in discover_plugins()}

        assert (records["sqli"].version, records["sqli"].metadata.category) == ("0.3.0", "scanner")
        assert records["sqli"].metadata.consumes == ["flow"]
        assert records["sqli"].metadata.produces == ["finding"]

    def test_entry_point_reference_is_the_repo_relative_module_path(self):
        records = {record.name: record for record in discover_plugins()}

        assert records["sqli"].entry_point == "pwnproxy/plugins/scanners/sqli/plugin.py"

    def test_a_broken_builtin_is_reported_without_hiding_the_others(self, tmp_path):
        scanners = tmp_path / "scanners"
        (scanners / "good").mkdir(parents=True)
        (scanners / "good" / "plugin.py").write_text(
            _plugin_source("GoodPlugin", "good"), encoding="utf-8"
        )
        (scanners / "broken").mkdir()
        (scanners / "broken" / "plugin.py").write_text(
            "import a_module_that_does_not_exist\n", encoding="utf-8"
        )

        records = discover_plugins(scanners)

        assert [(r.name, r.error is None) for r in records] == [("broken", False), ("good", True)]
        assert records[0].error.startswith("ModuleNotFoundError")
        assert callable(records[1].factory)


class TestInstalledDiscovery:
    def test_entry_point_class_is_discovered_as_installed(self, install_fake_plugin):
        fake = install_fake_plugin()

        record = {r.name: r for r in discover_plugins()}[fake.plugin_name]

        assert (
            record.source,
            record.package,
            record.version,
            record.entry_point,
            record.error,
        ) == (SOURCE_INSTALLED, "pwnproxy-pro", "2.0.0", f"{fake.module}:FakeScanner", None)
        assert callable(record.factory)

    def test_entry_point_may_be_an_instance(self, install_fake_plugin):
        fake = install_fake_plugin()
        fake.module_path.write_text(
            fake.module_path.read_text(encoding="utf-8") + "\nINSTANCE = FakeScanner()\n",
            encoding="utf-8",
        )
        # Rewrite the entry point to the module-level instance.
        (fake.dist_info / "entry_points.txt").write_text(
            f"[{ENTRY_POINT_GROUP}]\n{fake.plugin_name} = {fake.module}:INSTANCE\n", encoding="utf-8"
        )

        record = {r.name: r for r in discover_plugins()}[fake.plugin_name]

        assert (record.source, record.error) == (SOURCE_INSTALLED, None)
        assert callable(record.factory)

    def test_package_without_entry_point_is_not_in_the_catalog(self, install_fake_plugin):
        fake = install_fake_plugin()
        (fake.dist_info / "entry_points.txt").unlink()

        assert {record.source for record in discover_plugins()} == {SOURCE_BUILTIN}

    def test_entry_point_in_another_group_is_ignored(self, install_fake_plugin):
        fake = install_fake_plugin(group="pwnproxy.not-plugins")

        assert fake.plugin_name not in {record.name for record in discover_plugins()}

    def test_a_module_that_does_not_import_is_an_error_entry(self, install_fake_plugin):
        fake = install_fake_plugin(target="module_that_does_not_exist:Thing")

        record = {r.name: r for r in discover_plugins()}[fake.plugin_name]

        assert (record.source, record.factory, record.error.startswith("import failed")) == (
            SOURCE_INSTALLED,
            None,
            True,
        )

    def test_a_target_that_is_not_a_plugin_is_an_error_entry(self, install_fake_plugin):
        fake = install_fake_plugin(source="OBJECT = 42\n", class_name="OBJECT")

        record = {r.name: r for r in discover_plugins()}[fake.plugin_name]

        assert (record.factory, "PwnPlugin subclass or instance" in record.error) == (None, True)

    def test_a_plugin_without_metadata_is_an_error_entry(self, install_fake_plugin):
        fake = install_fake_plugin(
            source="from pwnproxy.plugins.core.base import PwnPlugin\n\nclass Bare(PwnPlugin):\n    pass\n",
            class_name="Bare",
        )

        record = {r.name: r for r in discover_plugins()}[fake.plugin_name]

        assert (record.factory, record.error) == (None, "plugin has no metadata (name/version are required)")

    def test_version_falls_back_to_the_package_version(self, install_fake_plugin):
        fake = install_fake_plugin(plugin_version="")

        record = {r.name: r for r in discover_plugins()}[fake.plugin_name]

        assert (record.version, record.package) == (fake.package_version, fake.package)

    def test_name_collision_keeps_the_builtin_and_reports_the_installed(self, install_fake_plugin):
        install_fake_plugin(dist="pwnproxy-shadow", plugin_name="sqli")

        records = discover_plugins()
        same_name = [record for record in records if record.name == "sqli"]

        assert [(r.source, r.error) for r in same_name] == [
            (SOURCE_BUILTIN, None),
            (SOURCE_INSTALLED, "name collision with builtin 'sqli'"),
        ]
        assert same_name[0].factory is not None
        assert same_name[1].factory is None


class TestCatalogOrder:
    def test_builtins_come_first_then_name_ascending_and_installed_last(self, install_fake_plugin):
        install_fake_plugin(dist="pwnproxy-zeta", plugin_name="zeta-plugin")
        install_fake_plugin(dist="pwnproxy-alpha", plugin_name="alpha-plugin")

        names = [(record.source, record.name) for record in discover_plugins()]

        assert names == [
            *[(SOURCE_BUILTIN, name) for name in BUILTIN_NAMES],
            (SOURCE_INSTALLED, "alpha-plugin"),
            (SOURCE_INSTALLED, "zeta-plugin"),
        ]

    def test_two_calls_return_the_same_order(self, install_fake_plugin):
        install_fake_plugin()

        first = [(r.source, r.name, r.package, r.error) for r in discover_plugins()]
        second = [(r.source, r.name, r.package, r.error) for r in discover_plugins()]

        assert first == second

    def test_builtins_can_be_discovered_from_a_custom_directory(self, tmp_path):
        scanners = tmp_path / "scanners"
        (scanners / "only-one").mkdir(parents=True)
        (scanners / "only-one" / "plugin.py").write_text(
            _plugin_source("OnlyOnePlugin", "only-one"), encoding="utf-8"
        )

        records = discover_plugins(scanners)

        assert [(r.name, r.source) for r in records] == [("only-one", SOURCE_BUILTIN)]

    def test_a_missing_scanners_directory_is_not_an_error(self, tmp_path):
        assert discover_plugins(tmp_path / "nope") == []


class TestFakePluginHelper:
    def test_the_installed_module_is_really_importable(self, install_fake_plugin):
        """Guard the fixture itself: the entry point must reference real code."""
        fake = install_fake_plugin()

        module = importlib.import_module(fake.module)

        assert module.FakeScanner().metadata.name == fake.plugin_name


class TestInstalledPluginIsolation:
    """The suite must not depend on which plugins the machine has installed.

    ``isolated_installed_plugins`` (``tests/conftest.py``) is autouse for the
    whole session: only the fake distributions :func:`install_fake_plugin` put
    under ``tmp_path`` reach ``discover_plugins``. A real package installed in
    the environment (``pip install pwnproxy-pro``) is still importable and still
    declares its entry point, but it must not appear in the catalog a test sees.
    """

    def test_a_distribution_outside_the_test_tree_is_invisible(self, monkeypatch):
        import importlib.metadata
        import shutil
        import tempfile
        from pathlib import Path

        tree = Path(tempfile.mkdtemp(prefix="pwnproxy-real-plugin-"))
        try:
            module = "real_pwnproxy_plugin_probe"
            (tree / f"{module}.py").write_text(
                _plugin_source("RealPlugin", "real-plugin"), encoding="utf-8"
            )
            dist_info = tree / "pwnproxy_real_probe-9.9.9.dist-info"
            dist_info.mkdir()
            (dist_info / "METADATA").write_text(
                "Metadata-Version: 2.1\nName: pwnproxy-real-probe\nVersion: 9.9.9\n",
                encoding="utf-8",
            )
            (dist_info / "entry_points.txt").write_text(
                f"[{ENTRY_POINT_GROUP}]\nreal-plugin = {module}:RealPlugin\n", encoding="utf-8"
            )
            monkeypatch.syspath_prepend(str(tree))

            # Production enumeration (not the patched seam) does see it: the
            # distribution is a valid one, the filter is what hides it.
            enumerated = [ep.name for ep in importlib.metadata.entry_points(group=ENTRY_POINT_GROUP)]
            names = [record.name for record in discover_plugins()]

            assert ("real-plugin" in enumerated, "real-plugin" in names) == (True, False)
        finally:
            shutil.rmtree(tree, ignore_errors=True)

