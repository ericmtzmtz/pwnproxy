"""``[plugin.activation]``: read, default rule and atomic write.

The table decides what the loader loads, so the reader must never fail at
startup and the writer must never truncate the user's file. The write is
line-based on purpose: the rest of ``config.toml`` (comments, key order and
other tables) has to come out byte-identical.
"""

import tomllib

import pytest

from pwnproxy.plugins.core.config import (
    ActivationConfigError,
    config_path,
    load_activation,
    load_config,
    plugin_enabled,
    set_plugin_enabled,
)


class TestReader:
    def test_no_file_means_no_explicit_activation(self, activation_config):
        assert activation_config("") == config_path()
        config_path().unlink()

        assert load_activation() == {}

    def test_reads_the_activation_table(self, activation_config):
        activation_config('[plugin.activation]\nsqli = false\nauth-matrix = true\n')

        assert load_activation() == {"sqli": False, "auth-matrix": True}

    def test_non_boolean_values_are_ignored(self, activation_config):
        activation_config('[plugin.activation]\nsqli = "no"\nxss = true\n')

        assert load_activation() == {"xss": True}

    def test_broken_toml_does_not_raise(self, activation_config):
        activation_config("[plugin.activation\nsqli = false\n")

        assert load_activation() == {}

    def test_other_tables_keep_working(self, activation_config):
        activation_config('[triage]\nenabled = false\n\n[plugin.activation]\nsqli = false\n')

        assert load_activation() == {"sqli": False}
        assert load_config()["activation"] == {"sqli": False}


class TestDefaultRule:
    def test_builtin_is_enabled_and_installed_is_disabled_by_default(self):
        assert (plugin_enabled("sqli", "builtin", {}), plugin_enabled("pro-matrix", "installed", {})) == (
            True,
            False,
        )

    def test_the_table_overrides_the_default(self):
        activation = {"sqli": False, "pro-matrix": True}

        assert (plugin_enabled("sqli", "builtin", activation), plugin_enabled("pro-matrix", "installed", activation)) == (
            False,
            True,
        )


class TestWriter:
    def test_creates_the_table_when_missing(self, activation_config):
        activation_config("[triage]\nenabled = true\n")

        set_plugin_enabled("alpha", True)

        written = tomllib.loads(config_path().read_text(encoding="utf-8"))
        assert written == {"triage": {"enabled": True}, "plugin": {"activation": {"alpha": True}}}

    def test_creates_the_file_when_missing(self, activation_config):
        activation_config("")
        config_path().unlink()

        set_plugin_enabled("alpha", False)

        assert tomllib.loads(config_path().read_text(encoding="utf-8")) == {
            "plugin": {"activation": {"alpha": False}}
        }

    def test_replaces_an_existing_entry_without_duplicating_it(self, activation_config):
        activation_config('[plugin.activation]\nalpha = false\nbeta = true\n')

        set_plugin_enabled("alpha", True)

        text = config_path().read_text(encoding="utf-8")
        assert tomllib.loads(text)["plugin"]["activation"] == {"alpha": True, "beta": True}
        assert text.count("alpha =") == 1

    def test_the_rest_of_the_file_is_preserved_byte_for_byte(self, activation_config):
        original = (
            "# top comment\n"
            "[triage]\n"
            "enabled = true   # inline comment\n"
            "\n"
            "[plugin]\n"
            "plugin_timeout = 45\n"
            "\n"
            "[plugin.activation]\n"
            "alpha = false\n"
            "\n"
            "[plugin.watchdog]\n"
            "threshold = 2\n"
        )
        activation_config(original)

        set_plugin_enabled("alpha", True)

        assert config_path().read_text(encoding="utf-8") == original.replace("alpha = false", "alpha = true")

    def test_quoted_and_bare_keys_are_the_same_entry(self, activation_config):
        activation_config('[plugin.activation]\n"auth.matrix" = false\n')

        set_plugin_enabled("auth.matrix", True)

        text = config_path().read_text(encoding="utf-8")
        assert tomllib.loads(text)["plugin"]["activation"] == {"auth.matrix": True}
        assert text.count("auth.matrix") == 1

    def test_a_name_that_is_not_a_bare_key_is_quoted(self, activation_config):
        activation_config("")

        set_plugin_enabled("weird name", True)

        assert tomllib.loads(config_path().read_text(encoding="utf-8"))["plugin"]["activation"] == {
            "weird name": True
        }

    def test_no_temporary_file_is_left_behind(self, activation_config):
        activation_config("")

        set_plugin_enabled("alpha", True)

        assert sorted(path.name for path in config_path().parent.iterdir()) == ["config.toml"]

    def test_an_unwritable_config_raises_and_leaves_the_file_alone(self, activation_config, tmp_path):
        activation_config('[plugin.activation]\nalpha = false\n')
        # A directory where the file should be: readable neither as a file nor
        # replaceable, which is the portable way to simulate broken permissions.
        config_path().unlink()
        config_path().mkdir()

        with pytest.raises(ActivationConfigError):
            set_plugin_enabled("alpha", True)

        assert config_path().is_dir()
        assert list(tmp_path.iterdir()) == [config_path()]
