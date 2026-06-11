import tomllib
from pathlib import Path
from typing import Optional


def load_config() -> dict:
    config_dir = Path.home() / ".pwnproxy"
    config_path = config_dir / "config.toml"
    defaults = {
        "registry": None,
        "plugin_timeout": 30,
        "watchdog_threshold": 3,
    }
    if not config_path.exists():
        return defaults
    try:
        data = tomllib.loads(config_path.read_text(encoding="utf-8"))
        plugin_section = data.get("plugin", {})
        return {**defaults, **plugin_section}
    except Exception:
        return defaults


def get_registry_url() -> Optional[str]:
    return load_config().get("registry")
