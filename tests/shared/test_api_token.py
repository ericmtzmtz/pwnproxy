"""The API token files: generation, creation, rotation and permissions.

Everything here reads the contract from ``specs/api-auth/spec.md``:

* 43 characters of ``[A-Za-z0-9_-]``, no newline in the file;
* created on first server start, never rotated by a second start;
* ``PWNPROXY_API_TOKEN`` is accepted and never written;
* a permission failure never raises (the token is already usable);
* ``0o600`` on POSIX, one-ACE protected DACL on Windows;
* rotation touches one scope only and keeps the permissions.

``PWNPROXY_CONFIG_DIR`` always points at ``tmp_path`` and the suite token env var
is removed where the test needs "no token anywhere": the real ``~/.pwnproxy`` is
never read or written.
"""

from __future__ import annotations

import os
import re
import secrets
from pathlib import Path

import pytest

from pwnproxy.shared.api_acl import acl_ace_count, file_mode, restrict_to_current_user
from pwnproxy.shared.api_token import (
    API_TOKEN_FILE,
    MCP_TOKEN_FILE,
    SCOPE_AGENT,
    SCOPE_FULL,
    SCOPES,
    TOKEN_ENV,
    ensure_tokens,
    find_token,
    generate_token,
    load_server_tokens,
    read_token,
    rotate_token,
    scope_for,
    token_path,
    write_token,
)

TOKEN_CHARSET = re.compile(r"^[A-Za-z0-9_-]+$")


@pytest.fixture(autouse=True)
def isolated_tokens(tmp_path, monkeypatch) -> Path:
    """Point the token files at an empty directory and drop the env token."""
    monkeypatch.setenv("PWNPROXY_CONFIG_DIR", str(tmp_path))
    monkeypatch.delenv(TOKEN_ENV, raising=False)
    return tmp_path


class TestGenerateToken:
    def test_length_and_charset(self):
        """43 url-safe characters: valid inside ``Sec-WebSocket-Protocol``."""
        token = generate_token()

        assert (len(token), bool(TOKEN_CHARSET.match(token))) == (43, True)

    def test_two_tokens_differ(self):
        tokens = {generate_token() for _ in range(50)}

        assert len(tokens) == 50


class TestPaths:
    def test_each_scope_has_its_own_file(self, isolated_tokens):
        assert (token_path(SCOPE_FULL), token_path(SCOPE_AGENT)) == (
            isolated_tokens / API_TOKEN_FILE,
            isolated_tokens / MCP_TOKEN_FILE,
        )

    def test_unknown_scope_is_rejected(self):
        with pytest.raises(ValueError, match="unknown token scope 'root'"):
            token_path("root")


class TestWriteAndRead:
    def test_the_file_holds_only_the_token(self, isolated_tokens):
        """No trailing newline: it would break ``$(cat api-token)`` in curl."""
        path = write_token(SCOPE_FULL, "abc-123_XYZ")
        write_token(SCOPE_AGENT, "agent-token")

        assert (path, path.read_text(encoding="utf-8"), read_token(SCOPE_FULL)) == (
            isolated_tokens / API_TOKEN_FILE,
            "abc-123_XYZ",
            "abc-123_XYZ",
        )

    def test_a_trailing_newline_is_tolerated_when_reading(self, isolated_tokens):
        """The user may edit the file by hand (or with an editor that adds one)."""
        (isolated_tokens / API_TOKEN_FILE).write_text("pasted-token\n", encoding="utf-8")

        assert read_token(SCOPE_FULL) == "pasted-token"

    def test_an_empty_file_is_no_token(self, isolated_tokens):
        (isolated_tokens / API_TOKEN_FILE).write_text("\n", encoding="utf-8")

        assert (read_token(SCOPE_FULL), read_token(SCOPE_AGENT)) == (None, None)

    def test_a_missing_file_is_no_token(self):
        assert read_token(SCOPE_AGENT) is None


class TestEnsureTokens:
    def test_first_start_creates_both_tokens(self):
        paths = ensure_tokens()

        first, second = read_token(SCOPE_FULL), read_token(SCOPE_AGENT)
        assert (
            sorted(paths) == sorted(SCOPES),
            first is not None and second is not None,
            first != second,
            len(first or ""),
        ) == (True, True, True, 43)

    def test_a_second_start_does_not_rotate(self):
        """A restart must not invalidate the token the Web UI already has."""
        ensure_tokens()
        before = {scope: read_token(scope) for scope in SCOPES}

        ensure_tokens()

        assert {scope: read_token(scope) for scope in SCOPES} == before

    def test_only_creates_the_missing_one(self):
        write_token(SCOPE_FULL, "keep-me")

        ensure_tokens()

        assert (read_token(SCOPE_FULL), read_token(SCOPE_AGENT)) == ("keep-me", read_token(SCOPE_AGENT))


class TestEnvironmentToken:
    def test_the_env_token_is_accepted_as_full(self, monkeypatch):
        monkeypatch.setenv(TOKEN_ENV, "from-the-ci")

        assert (scope_for("from-the-ci"), load_server_tokens().get("from-the-ci")) == (SCOPE_FULL, SCOPE_FULL)

    def test_the_env_is_never_written_to_disk(self, isolated_tokens, monkeypatch):
        monkeypatch.setenv(TOKEN_ENV, "from-the-ci")
        ensure_tokens()

        written = {
            path.name: path.read_text(encoding="utf-8")
            for path in isolated_tokens.iterdir()
            if path.is_file()
        }
        assert "from-the-ci" not in written.values()

    def test_an_empty_env_is_ignored(self, monkeypatch):
        monkeypatch.setenv(TOKEN_ENV, "   ")

        assert load_server_tokens() == {}


class TestLookup:
    def test_each_scope_is_found_with_its_source(self):
        write_token(SCOPE_FULL, "full-token")
        write_token(SCOPE_AGENT, "agent-token")

        assert (
            find_token("full-token"),
            find_token("agent-token"),
            find_token("nope"),
            find_token(None),
            find_token(""),
        ) == ((SCOPE_FULL, API_TOKEN_FILE), (SCOPE_AGENT, MCP_TOKEN_FILE), None, None, None)

    def test_a_non_ascii_token_does_not_raise(self):
        """``compare_digest`` over ``str`` raises on non-ASCII; over bytes it does not."""
        write_token(SCOPE_FULL, "full-token")

        assert (scope_for("tökén"), scope_for("full-token")) == (None, SCOPE_FULL)

    def test_the_env_wins_over_a_file_with_the_same_value(self, monkeypatch):
        write_token(SCOPE_AGENT, "same-value")
        monkeypatch.setenv(TOKEN_ENV, "same-value")

        assert find_token("same-value") == (SCOPE_FULL, "env")


class TestRotation:
    def test_rotate_changes_only_the_requested_scope(self):
        write_token(SCOPE_FULL, "old-full")
        write_token(SCOPE_AGENT, "old-agent")

        rotated = rotate_token(SCOPE_AGENT)

        assert (
            len(rotated),
            rotated != "old-agent",
            read_token(SCOPE_AGENT),
            read_token(SCOPE_FULL),
        ) == (43, True, rotated, "old-full")

    def test_rotate_keeps_the_permissions(self):
        write_token(SCOPE_FULL, "old-full")
        before = file_mode(token_path(SCOPE_FULL)) if os.name != "nt" else acl_ace_count(token_path(SCOPE_FULL))

        rotate_token(SCOPE_FULL)

        after = file_mode(token_path(SCOPE_FULL)) if os.name != "nt" else acl_ace_count(token_path(SCOPE_FULL))
        assert after == before


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions are not meaningful on Windows")
class TestPosixPermissions:
    def test_a_new_token_file_is_0600(self):
        write_token(SCOPE_FULL, "abc")

        assert file_mode(token_path(SCOPE_FULL)) == 0o600

    def test_an_existing_world_readable_file_is_fixed(self):
        """The mode is applied to the destination, not only at creation time."""
        path = token_path(SCOPE_FULL)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("old", encoding="utf-8")
        os.chmod(path, 0o644)

        write_token(SCOPE_FULL, "new")

        assert file_mode(path) == 0o600


@pytest.mark.skipif(os.name != "nt", reason="the DACL branch only exists on Windows")
class TestWindowsAcl:
    def test_the_dacl_has_exactly_one_ace(self):
        """Inherited ``Authenticated Users``/``Administrators`` would make it > 1."""
        path = write_token(SCOPE_FULL, "abc")

        assert acl_ace_count(path) == 1

    def test_rotating_keeps_the_single_ace(self):
        path = write_token(SCOPE_FULL, "abc")

        rotate_token(SCOPE_FULL)

        assert acl_ace_count(path) == 1


class TestFailureHandling:
    def test_a_restriction_failure_returns_false_instead_of_raising(self, tmp_path):
        """A refused DACL must not stop the server; it is logged and ignored."""
        assert restrict_to_current_user(tmp_path / "does-not-exist") is False

    def test_the_token_stays_usable_when_the_restriction_fails(self, monkeypatch, tmp_path):
        import pwnproxy.shared.api_token as api_token_module

        monkeypatch.setattr(api_token_module, "restrict_to_current_user", lambda _path: False)

        path = write_token(SCOPE_FULL, secrets.token_urlsafe(32))

        assert read_token(SCOPE_FULL) == path.read_text(encoding="utf-8")
