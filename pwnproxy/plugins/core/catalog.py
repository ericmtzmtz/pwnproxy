"""Single source of truth for plugin discovery.

Everything that needs to know *which plugins exist* asks this module:
the live proxy (:meth:`UniversalPluginLoader.refresh_catalog`), the one-shot
scan path (``POST /api/v1/scan`` and ``pwnproxy scan url``), the scanner
trigger endpoint, ``GET /api/v1/plugins``, the TUI and ``pwnproxy plugin list``.
No other module (and no client) keeps its own list of names.

Two sources feed the catalog:

* **built-ins** — the ``plugin.py`` modules under ``pwnproxy/plugins/scanners/``
  (the same tree the loader used to walk on its own);
* **installed packages** — distributions that declare an entry point in the
  ``pwnproxy.plugins`` group::

      [project.entry-points."pwnproxy.plugins"]
      authorization-matrix = "pwnproxy_pro.matrix:AuthorizationMatrixPlugin"

  The value resolves to a :class:`~pwnproxy.plugins.core.base.PwnPlugin`
  subclass (instantiated without arguments) or to an already built instance.

Failure isolation is a hard requirement: importing, instantiating or resolving
a broken plugin must never abort the discovery of the others. Every failure is
captured in the record's ``error`` and surfaced by ``GET /api/v1/plugins``. Note
that resolving an entry point *imports* the package (module-level code runs even
while the plugin stays disabled); that is part of the contract and is documented
in ``docs/plugin-architecture.md``. A class entry point is only *instantiated*
when the loader actually loads it (or when its metadata is not a class
attribute), so a disabled or colliding plugin never runs its constructor.

The module also owns the one-shot scan primitives (``scan_config`` and
``build_scan_loader``) that used to live in ``apps/terminal/cli/scan.py`` — the
transport layer must not import ``apps/`` (see ``tests/architecture``).
"""

from __future__ import annotations

import importlib.metadata
import importlib.util
import logging
from collections.abc import Iterable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from pwnproxy.plugins.core.base import PluginMetadata, PwnPlugin
from pwnproxy.plugins.core.config import load_activation
from pwnproxy.shared.ports import DEFAULT_CALLBACK_PORT

logger = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "pwnproxy.plugins"
SOURCE_BUILTIN = "builtin"
SOURCE_INSTALLED = "installed"
BUILTIN_PACKAGE = "pwnproxy"


@dataclass(frozen=True)
class PluginRecord:
    """One plugin as the catalog sees it.

    Attributes:
        name: Plugin name from its metadata; unique in the catalog.
        source: ``"builtin"`` (shipped in the tree) or ``"installed"`` (from a
            distribution entry point).
        package: Distribution that provides it (``"pwnproxy"`` for built-ins).
        version: Plugin version when it declares one, otherwise the package's.
        entry_point: ``"module:Class"`` for installed plugins; the module path
            for built-ins.
        factory: Callable returning a plugin instance, or ``None`` when the
            plugin could not be resolved (see ``error``).
        error: Why discovery failed, or ``None`` when the plugin is usable.
        metadata: Metadata captured at discovery time (``None`` for a plugin
            whose import or entry point failed). Used to publish the optional
            fields of ``GET /api/v1/plugins`` even when the plugin is disabled
            and therefore not instantiated by the loader.
    """

    name: str
    source: str
    package: str
    version: str
    entry_point: str
    factory: Any | None = None
    error: str | None = None
    metadata: PluginMetadata | None = None


def builtin_scanners_path() -> Path:
    """Return the directory that holds the built-in scanner packages."""
    from pwnproxy import __file__ as _pwnproxy_init

    return Path(_pwnproxy_init).parent / "plugins" / "scanners"


def discover_plugins(scanners_path: str | Path | None = None) -> list[PluginRecord]:
    """Build the catalog: built-ins first, then installed plugins, by name.

    Args:
        scanners_path: Directory to scan for built-in plugins; defaults to
            ``pwnproxy/plugins/scanners``.

    Returns:
        Every discovered plugin, sorted by ``source`` (built-ins first) and then
        ``name`` ascending. Broken plugins are included with ``error`` set and
        ``factory`` ``None``; they are never dropped silently.
    """
    builtins = _discover_builtins(scanners_path)
    taken = {record.name for record in builtins}
    installed: list[PluginRecord] = []
    for record in _discover_installed():
        if record.name in taken:
            installed.append(
                replace(
                    record,
                    factory=None,
                    error=record.error or f"name collision with builtin '{record.name}'",
                )
            )
            continue
        taken.add(record.name)
        installed.append(record)
    return sorted([*builtins, *installed], key=lambda r: (0 if r.source == SOURCE_BUILTIN else 1, r.name))


def _error_text(exc: BaseException) -> str:
    """Render an exception as ``Type: message`` for the catalog/log."""
    return f"{type(exc).__name__}: {exc}"


def _normalized_metadata(plugin: PwnPlugin) -> PluginMetadata | None:
    """Return the plugin metadata, filling ``category`` from the class default.

    Built-in plugins declare ``ScannerPlugin.category = "scanner"`` on the class
    but leave ``PluginMetadata.category`` empty, so ``GET /plugins`` would report
    no category at all. Clients (the Web UI scanner picker) filter on it.
    """
    metadata = getattr(plugin, "metadata", None)
    if metadata is None:
        return None
    if not metadata.category:
        class_category = getattr(plugin, "category", "")
        if class_category:
            return replace(metadata, category=class_category)
    return metadata


def _first_scanner_class(module: Any) -> type[PwnPlugin] | None:
    """Return the first plugin class defined in a built-in ``plugin.py`` module."""
    from pwnproxy.plugins.core.base import ScannerPlugin

    for obj in vars(module).values():
        if isinstance(obj, type) and issubclass(obj, ScannerPlugin) and obj is not ScannerPlugin:
            return obj
    return None


def _discover_builtins(scanners_path: str | Path | None = None) -> list[PluginRecord]:
    """Discover the plugins that ship inside ``pwnproxy/plugins/scanners/``."""
    root = Path(scanners_path) if scanners_path is not None else builtin_scanners_path()
    if not root.is_dir():
        logger.warning("Scanners directory not found: %s", root)
        return []

    records: list[PluginRecord] = []
    for entry in sorted(root.iterdir()):
        if not entry.is_dir():
            continue
        plugin_file = entry / "plugin.py"
        if not plugin_file.exists():
            continue
        reference = _relative_reference(plugin_file, root)
        try:
            spec = importlib.util.spec_from_file_location(f"{entry.name}.plugin", str(plugin_file))
            if spec is None or spec.loader is None:
                records.append(PluginRecord(
                    name=entry.name, source=SOURCE_BUILTIN, package=BUILTIN_PACKAGE,
                    version="", entry_point=reference,
                    error=f"could not build an import spec for {reference}",
                ))
                continue
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            plugin_class = _first_scanner_class(module)
            if plugin_class is None:
                continue
            instance = plugin_class()
            metadata = _normalized_metadata(instance)
            name = (metadata.name if metadata else "") or entry.name
            records.append(PluginRecord(
                name=name, source=SOURCE_BUILTIN, package=BUILTIN_PACKAGE,
                version=(metadata.version if metadata else "") or "",
                entry_point=reference, factory=plugin_class, metadata=metadata,
            ))
        except Exception as exc:  # one broken built-in must not hide the rest
            logger.warning("Failed to discover builtin plugin %s: %s", entry.name, exc)
            records.append(PluginRecord(
                name=entry.name, source=SOURCE_BUILTIN, package=BUILTIN_PACKAGE,
                version="", entry_point=reference, error=_error_text(exc),
            ))
    return records


def _relative_reference(plugin_file: Path, root: Path) -> str:
    """Return a repo-relative path for a built-in plugin module.

    ``root`` is the scanners directory (``<repo>/pwnproxy/plugins/scanners``), so
    its great-grandparent is the repo root. Falls back to the absolute path for
    an out-of-tree scanners directory (tests point it at ``tmp_path``).
    """
    try:
        return plugin_file.relative_to(root.parent.parent.parent).as_posix()
    except ValueError:
        return plugin_file.as_posix()


def _discover_installed() -> list[PluginRecord]:
    """Discover plugins declared by installed distributions' entry points."""
    try:
        entry_points = list(importlib.metadata.entry_points(group=ENTRY_POINT_GROUP))
    except Exception as exc:  # metadata backend broken: built-ins still work
        logger.warning("Could not enumerate the %s entry points: %s", ENTRY_POINT_GROUP, exc)
        return []

    records: list[PluginRecord] = []
    for entry_point in sorted(entry_points, key=lambda ep: (ep.name, ep.value)):
        distribution = getattr(entry_point, "dist", None)
        package = (getattr(distribution, "name", "") or "") or entry_point.name
        package_version = (getattr(distribution, "version", "") or "") or ""
        try:
            target = entry_point.load()
        except Exception as exc:
            logger.warning("Plugin import failed for %s (%s): %s", entry_point.name, package, exc)
            records.append(PluginRecord(
                name=entry_point.name, source=SOURCE_INSTALLED, package=package,
                version=package_version, entry_point=entry_point.value,
                error=f"import failed ({_error_text(exc)})",
            ))
            continue
        plugin, error = _coerce_plugin(target)
        if plugin is None:
            records.append(PluginRecord(
                name=entry_point.name, source=SOURCE_INSTALLED, package=package,
                version=package_version, entry_point=entry_point.value, error=error,
            ))
            continue
        metadata = _normalized_metadata(plugin)
        records.append(PluginRecord(
            name=(metadata.name if metadata else "") or entry_point.name,
            source=SOURCE_INSTALLED,
            package=package,
            version=(metadata.version if metadata else "") or package_version,
            entry_point=entry_point.value,
            factory=(lambda target=target: target() if isinstance(target, type) else target),
            metadata=metadata,
        ))
    return records


def _coerce_plugin(target: Any) -> tuple[Any | None, str | None]:
    """Validate an entry-point target without running a plugin that will not load.

    Returns:
        ``(plugin, None)`` on success or ``(None, reason)`` when the target is
        not a plugin, not a ``PwnPlugin`` subclass/instance, has no metadata or
        cannot be instantiated.

    A subclass that publishes ``metadata`` as a class attribute (every built-in
    does) is returned **as the class**: discovery must not execute the
    constructor of a plugin that ends up disabled or in collision with a
    built-in. The loader instantiates it later through ``record.factory``.
    """
    try:
        if isinstance(target, PwnPlugin):
            plugin = target
        elif isinstance(target, type) and issubclass(target, PwnPlugin):
            class_metadata = getattr(target, "metadata", None)
            usable = isinstance(class_metadata, PluginMetadata)
            plugin = target if usable else target()
        else:
            return None, (
                "entry point must resolve to a PwnPlugin subclass or instance, "
                f"got {type(target).__name__}"
            )
    except Exception as exc:
        return None, f"instantiation failed ({_error_text(exc)})"
    if getattr(plugin, "metadata", None) is None:
        return None, "plugin has no metadata (name/version are required)"
    return plugin, None


def scan_config(
    detection_depth: str = "fast",
    evasion_level: str = "none",
    callback_port: int = DEFAULT_CALLBACK_PORT,
) -> dict:
    """Map request parameters to the plugin config keys read in ``on_load()``.

    ``callback_port`` is the port this process' OOB callback listener is bound
    to; only the SSRF plugin reads it (it goes into the OOB payloads), the rest
    ignore the extra key. Without it the SSRF payloads would knock on the
    default port while the listener sits elsewhere.

    Args:
        detection_depth: ``fast`` | ``standard`` | ``deep``.
        evasion_level: ``none`` | ``light`` | ``aggressive``.
        callback_port: Port of the local OOB listener.

    Returns:
        The ``PluginContext.config`` dict handed to every loaded plugin.
    """
    return {
        "depth": detection_depth,
        "evasion_level": evasion_level,
        "callback_port": callback_port,
    }


def _catalog_enabled(records: Iterable[PluginRecord], activation: dict[str, bool]) -> set[str]:
    """Return the names that are enabled according to ``[plugin.activation]``."""
    return {
        record.name
        for record in records
        if record.factory is not None and activation.get(record.name, record.source == SOURCE_BUILTIN)
    }


async def build_scan_loader(
    scanners: set[str] | None = None,
    disabled_plugins: Iterable[str] | None = None,
    config: dict | None = None,
) -> Any:
    """Build a throw-away loader for a one-shot scan.

    The set of scanners comes from :func:`discover_plugins`, never from a
    hardcoded registry: built-ins and enabled installed plugins both qualify.

    Args:
        scanners: Names to load; ``None`` (or empty) means "every enabled
            plugin in the catalog".
        disabled_plugins: Names that must not run even if requested. ``None``
            means "ask the activation config"; the API passes the live loader's
            effective state so a runtime toggle is honoured.
        config: ``PluginContext.config`` for every plugin (see
            :func:`scan_config`).

    Returns:
        A ``PluginLoader`` with the requested plugins already loaded.

    Raises:
        ValueError: a requested name is not in the catalog, or it is in the
            catalog but could not be resolved (broken plugin).
    """
    from pwnproxy.plugins.core.loader import PluginLoader

    records = discover_plugins()
    by_name = {record.name: record for record in records}
    alias = {"command_injection": "command-injection"}
    plugin_config = config or {}

    if disabled_plugins is None:
        enabled_names = _catalog_enabled(records, load_activation())
    else:
        blocked = set(disabled_plugins)
        enabled_names = {record.name for record in records if record.name not in blocked}

    if scanners:
        wanted: list[str] = []
        for raw in scanners:
            name = alias.get(raw, raw)
            record = by_name.get(name)
            if record is None:
                raise ValueError(f"Unknown scanner: {raw}")
            if record.error:
                raise ValueError(f"Scanner '{raw}' failed to load: {record.error}")
            if name not in wanted:
                wanted.append(name)
        targets = [by_name[name] for name in wanted]
    else:
        targets = [record for record in records if record.name in enabled_names]

    loader = PluginLoader()
    for record in targets:
        if record.name not in enabled_names or record.error or record.factory is None:
            continue
        await loader.load_builtin(record.factory(), config=plugin_config)
    return loader
