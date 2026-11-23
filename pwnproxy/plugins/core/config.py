"""User-level configuration for the plugin system.

Two things live here:

* the legacy ``[plugin]`` block (registry URL, timeout, watchdog threshold) read
  by :func:`load_config`;
* ``[plugin.activation]`` — the **machine-wide** on/off state of every plugin
  (``name = true|false``), read by :func:`load_activation` and rewritten
  atomically by :func:`set_plugin_enabled`.

Why the activation state is machine-wide and not per session: there is exactly
one plugin loader per process, so a per-session switch would silently change
what scans the live traffic when the user opens another session, and a plugin
package is a machine-level trust decision (it runs inside the proxy process).

Default when a name is absent from ``[plugin.activation]``: a **built-in** is
enabled (every install that never touched the file keeps today's behaviour) and
an **installed** package is disabled (a ``pip install`` must not start scanning
a client's traffic on its own).

The config directory defaults to ``~/.pwnproxy`` and can be overridden with
``PWNPROXY_CONFIG_DIR`` (used by the tests so they never touch the real file).
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import tempfile
import tomllib
from pathlib import Path

logger = logging.getLogger(__name__)

CONFIG_DIR_ENV = "PWNPROXY_CONFIG_DIR"
CONFIG_FILE_NAME = "config.toml"
ACTIVATION_HEADER = "[plugin.activation]"

#: Bare-key syntax per TOML; anything else has to be quoted.
_BARE_KEY_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_ACTIVATION_HEADER_RE = re.compile(r"^\s*\[\s*plugin\s*\.\s*activation\s*\]\s*(?:#.*)?$")
_ANY_TABLE_RE = re.compile(r"^\s*\[")
_KEY_LINE_RE = re.compile(r"""^\s*(?P<key>"(?:[^"\\]|\\.)*"|'[^']*'|[A-Za-z0-9_-]+)\s*=""")


class ActivationConfigError(RuntimeError):
    """Raised when the plugin activation state cannot be persisted.

    The API maps it to ``500`` and, crucially, the caller must leave the
    in-memory state untouched (a half-applied toggle would desynchronise the
    running process from the file).
    """


def config_dir() -> Path:
    """Return the configuration directory (``PWNPROXY_CONFIG_DIR`` wins)."""
    override = os.environ.get(CONFIG_DIR_ENV)
    if override:
        return Path(override)
    return Path.home() / ".pwnproxy"


def config_path() -> Path:
    """Return the path of ``config.toml`` inside :func:`config_dir`."""
    return config_dir() / CONFIG_FILE_NAME


def load_config() -> dict:
    """Read the legacy ``[plugin]`` block, merged over the built-in defaults."""
    defaults = {
        "registry": None,
        "plugin_timeout": 30,
        "watchdog_threshold": 3,
    }
    path = config_path()
    if not path.exists():
        return defaults
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        plugin_section = data.get("plugin", {})
        return {**defaults, **plugin_section}
    except Exception:
        return defaults


def get_registry_url() -> str | None:
    """Return the registry URL configured under ``[plugin]`` (``None`` if unset)."""
    return load_config().get("registry")


def load_activation() -> dict[str, bool]:
    """Return ``[plugin.activation]`` as ``{plugin_name: enabled}``.

    Missing file, missing table, unreadable TOML or non-boolean values all yield
    ``{}`` / skip the offending entry: this reader runs at startup and must
    never stop the proxy. Absent names fall back to :func:`plugin_enabled`'s
    rule (built-in enabled, installed disabled).
    """
    path = config_path()
    if not path.exists():
        return {}
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        logger.warning("Could not read %s: %s", path, exc)
        return {}
    table = data.get("plugin", {}).get("activation", {})
    if not isinstance(table, dict):
        logger.warning("[plugin.activation] in %s is not a table; ignoring it", path)
        return {}
    activation: dict[str, bool] = {}
    for name, value in table.items():
        if isinstance(value, bool):
            activation[str(name)] = value
        else:
            logger.warning("Ignoring [plugin.activation] %s = %r (expected true/false)", name, value)
    return activation


def plugin_enabled(name: str, source: str, activation: dict[str, bool] | None = None) -> bool:
    """Return the effective configured state of ``name``.

    Args:
        name: Plugin name as published by the catalog.
        source: ``"builtin"`` or ``"installed"``.
        activation: Table from :func:`load_activation`; re-read when omitted.

    Returns:
        ``True`` when ``[plugin.activation]`` says ``true``; when the name is
        absent, built-ins default to enabled and installed packages to disabled.
    """
    table = load_activation() if activation is None else activation
    if name in table:
        return table[name]
    return source == "builtin"


def set_plugin_enabled(name: str, enabled: bool) -> None:
    """Persist ``name = enabled`` under ``[plugin.activation]`` atomically.

    The rest of the file is preserved byte for byte (comments and key order
    included): rewriting the whole document from a parsed dict would silently
    drop the user's annotations. The new content is written to a temporary file
    in the same directory and moved over the original with ``os.replace``, so a
    crash never leaves a truncated config.

    Raises:
        ActivationConfigError: the directory/file is not readable or writable.
    """
    path = config_path()
    try:
        text = path.read_text(encoding="utf-8") if path.exists() else ""
    except OSError as exc:
        raise ActivationConfigError(f"could not read {path}: {exc}") from exc
    _atomic_write(path, _rewrite_activation(text, name, enabled))


def _atomic_write(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` via a temporary file + ``os.replace``."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".config-", suffix=".toml")
    except OSError as exc:
        raise ActivationConfigError(f"could not write {path}: {exc}") from exc
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except OSError as exc:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise ActivationConfigError(f"could not write {path}: {exc}") from exc


def _key_text(name: str) -> str:
    """Render ``name`` as a TOML key (quoting it when it is not a bare key)."""
    if _BARE_KEY_RE.match(name):
        return name
    escaped = name.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _key_matches(raw: str, name: str) -> bool:
    """Whether a TOML key as written in the file refers to ``name``."""
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] == '"':
        return raw[1:-1].replace('\\"', '"').replace("\\\\", "\\") == name
    if len(raw) >= 2 and raw[0] == raw[-1] == "'":
        return raw[1:-1] == name
    return raw == name


def _rewrite_activation(text: str, name: str, enabled: bool) -> str:
    """Return ``text`` with ``[plugin.activation] name = enabled`` applied.

    Line-based on purpose: only the activation table is touched, everything
    else in the file stays exactly as the user wrote it. Creates the table when
    it is missing and replaces (never duplicates) an existing entry for
    ``name``.
    """
    key_line = f"{_key_text(name)} = {'true' if enabled else 'false'}"
    lines = text.splitlines()

    start = next(
        (i for i, line in enumerate(lines) if _ACTIVATION_HEADER_RE.match(line)),
        None,
    )
    if start is None:
        while lines and not lines[-1].strip():
            lines.pop()
        if lines:
            lines.append("")
        lines.extend([ACTIVATION_HEADER, key_line])
        return "\n".join(lines) + "\n"

    end = next(
        (i for i in range(start + 1, len(lines)) if _ANY_TABLE_RE.match(lines[i])),
        len(lines),
    )
    body: list[str] = []
    written = False
    for line in lines[start + 1:end]:
        match = _KEY_LINE_RE.match(line)
        if match and _key_matches(match.group("key"), name):
            if not written:
                body.append(key_line)
                written = True
            continue
        body.append(line)
    trailing: list[str] = []
    while body and not body[-1].strip():
        trailing.insert(0, body.pop())
    if not written:
        body.append(key_line)
    body.extend(trailing)
    return "\n".join([*lines[: start + 1], *body, *lines[end:]]) + "\n"
