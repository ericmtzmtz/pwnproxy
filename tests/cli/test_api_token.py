"""``pwnproxy api token``: the way a human (or a script) gets the token.

The command is what the startup panel, the Web UI gate and the TUI/`MCP` error
messages tell the user to run, so its output is a contract:

* ``pwnproxy api token`` — the ``full`` token, the file it came from **and** the
  Web UI URL with ``#token=`` (that is how the UI is opened without pasting).
* ``pwnproxy api token --scope agent`` — the ``agent`` token, no URL.
* ``pwnproxy api token --rotate`` — a new token, and the warning that old clients
  get ``401``. The last test proves that against a real app: the old token is
  rejected and the new one works, without restarting anything.

Every case has its negative: no agent token at all, an unknown scope, and
``PWNPROXY_API_TOKEN`` set (the CI path), where ``--rotate`` must not write.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from apps.terminal.cli import app
from pwnproxy.shared.api_token import read_token, write_token
from pwnproxy.shared.ports import DEFAULT_WEB_PORT
from pwnproxy.transport.rest.app import app as api_app
from pwnproxy.transport.rest.auth import MISSING_TOKEN_DETAIL

runner = CliRunner()

WEB_UI = f"http://127.0.0.1:{DEFAULT_WEB_PORT}"


@pytest.fixture
def api_home(tmp_path, monkeypatch):
    """A config dir of its own, with no ``PWNPROXY_API_TOKEN``.

    The suite exports the env token for the API tests; this command has to be
    exercised exactly as on a machine where the variable is not set.
    """
    monkeypatch.setenv("PWNPROXY_CONFIG_DIR", str(tmp_path))
    monkeypatch.delenv("PWNPROXY_API_TOKEN", raising=False)
    return tmp_path


def test_show_creates_the_token_and_prints_the_web_ui_url(api_home):
    """No token yet (the API never ran): create it and print everything."""
    result = runner.invoke(app, ["api", "token"])

    token = (api_home / "api-token").read_text(encoding="utf-8")
    assert result.exit_code == 0
    assert result.output == (
        f"Token:   {token}\n"
        f"File:    {api_home / 'api-token'}\n"
        "Note:    the file did not exist; this command created it with the same "
        "restricted permissions the API uses.\n"
        f"Web UI:  {WEB_UI}/#token={token}\n"
    )


def test_show_agent_scope_prints_only_the_mcp_token(api_home):
    """``--scope agent``: the MCP token, its path, no UI URL, no ``api-token``."""
    write_token("full", "the-full-token")
    write_token("agent", "the-agent-token")

    result = runner.invoke(app, ["api", "token", "--scope", "agent"])

    assert result.exit_code == 0
    assert result.output == (
        "Token:   the-agent-token\n"
        f"File:    {api_home / 'mcp-token'}\n"
    )
    assert "the-full-token" not in result.output
    assert "#token=" not in result.output


def test_show_agent_scope_without_token_does_not_create_it(api_home):
    """The agent token is the API's to create: the command explains, creates nothing."""
    result = runner.invoke(app, ["api", "token", "--scope", "agent"])

    assert result.exit_code == 1
    assert (api_home / "mcp-token").exists() is False
    assert "pwnproxy start" in result.output
    assert "Token:" not in result.output


def test_show_with_env_token_names_the_variable_and_writes_nothing(api_home, monkeypatch):
    """``PWNPROXY_API_TOKEN`` wins over the file: say so, and create no file."""
    monkeypatch.setenv("PWNPROXY_API_TOKEN", "env-token-from-ci")

    result = runner.invoke(app, ["api", "token"])

    assert result.exit_code == 0
    assert result.output == (
        "Token:   env-token-from-ci\n"
        f"Source:  PWNPROXY_API_TOKEN (this value wins over {api_home / 'api-token'})\n"
        f"Web UI:  {WEB_UI}/#token=env-token-from-ci\n"
    )
    assert list(api_home.iterdir()) == []


def test_rotate_replaces_the_file_and_warns_about_401(api_home):
    """``--rotate``: new token on disk, and the warning that old clients fail."""
    write_token("full", "the-old-token")

    result = runner.invoke(app, ["api", "token", "--rotate"])

    new_token = read_token("full")
    assert result.exit_code == 0
    assert new_token != "the-old-token"
    assert result.output == (
        f"Rotated: {api_home / 'api-token'}\n"
        f"Token:   {new_token}\n"
        "Old clients get 401 on their next request; WebSockets already open keep "
        "working until they reconnect.\n"
        f"Web UI:  {WEB_UI}/#token={new_token}\n"
    )


def test_rotate_agent_scope_leaves_the_api_token_alone(api_home):
    """Rotating one scope must not touch the other file."""
    write_token("full", "the-full-token")
    write_token("agent", "the-old-agent-token")

    result = runner.invoke(app, ["api", "token", "--rotate", "--scope", "agent"])

    assert result.exit_code == 0
    assert read_token("full") == "the-full-token"
    assert read_token("agent") not in (None, "the-old-agent-token")
    assert "#token=" not in result.output


def test_rotate_with_env_token_writes_nothing(api_home, monkeypatch):
    """With the env token set the server would keep accepting the old value."""
    monkeypatch.setenv("PWNPROXY_API_TOKEN", "env-token-from-ci")

    result = runner.invoke(app, ["api", "token", "--rotate"])

    assert result.exit_code == 1
    assert list(api_home.iterdir()) == []
    assert "PWNPROXY_API_TOKEN is set" in result.output
    assert "rotat" in result.output.lower()
    assert "Token:" not in result.output


def test_unknown_scope_is_rejected(api_home):
    """A typo must not silently rotate the wrong token."""
    result = runner.invoke(app, ["api", "token", "--scope", "root"])

    assert result.exit_code == 2
    assert list(api_home.iterdir()) == []
    assert "use one of api, agent" in result.output


def test_rotation_invalidates_the_old_token_against_the_real_app(api_home):
    """End to end: the server re-reads the file, so the old token is dead at once."""
    write_token("full", "the-old-token")
    with TestClient(api_app) as client:
        before = client.get(
            "/api/v1/auth/whoami",
            headers={"Authorization": "Bearer the-old-token"},
        )
        assert (before.status_code, before.json()) == (200, {"scope": "full"})

        result = runner.invoke(app, ["api", "token", "--rotate"])
        assert result.exit_code == 0
        new_token = read_token("full")
        assert new_token not in (None, "the-old-token")

        old = client.get(
            "/api/v1/auth/whoami",
            headers={"Authorization": "Bearer the-old-token"},
        )
        new = client.get(
            "/api/v1/auth/whoami",
            headers={"Authorization": f"Bearer {new_token}"},
        )

    assert (old.status_code, old.json()) == (401, {"detail": MISSING_TOKEN_DETAIL})
    assert (new.status_code, new.json()) == (200, {"scope": "full"})
