"""Single source of truth for the pwnproxy configuration directory.

Why this module exists: ``config_dir()`` started inside
``pwnproxy/plugins/core/config.py``, but the API token files, the REST auth
middleware and the CLI need the same directory and they are **not** part of the
plugin layer. ``pwnproxy/shared/`` may not import ``pwnproxy.plugins`` (the
layering guard in ``tests/architecture/test_layering.py`` enforces the
``plugins -> shared`` direction), so the function moved here and the plugin
config module re-exports it: one implementation, two import paths.

``PWNPROXY_CONFIG_DIR`` wins over ``~/.pwnproxy``. The test suite points it at a
temporary directory for the whole session, so no test ever reads or writes the
developer's real configuration.
"""

from __future__ import annotations

import os
from pathlib import Path

#: Environment variable that overrides the configuration directory.
CONFIG_DIR_ENV = "PWNPROXY_CONFIG_DIR"

#: Default directory under the user's home.
DEFAULT_CONFIG_DIR_NAME = ".pwnproxy"

__all__ = ["CONFIG_DIR_ENV", "DEFAULT_CONFIG_DIR_NAME", "config_dir"]


def config_dir() -> Path:
    """Return the pwnproxy configuration directory.

    Returns:
        ``PWNPROXY_CONFIG_DIR`` when it is set and non-empty, else
        ``~/.pwnproxy``. The directory is not created here: callers create it
        when they actually write something.
    """
    override = os.environ.get(CONFIG_DIR_ENV)
    if override:
        return Path(override)
    return Path.home() / DEFAULT_CONFIG_DIR_NAME
