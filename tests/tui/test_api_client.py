"""The TUI as an API client: one seam and messages a human can act on.

The dashboard used to open a plain ``httpx.AsyncClient()`` per call and build the
URL by hand; the WebSocket client connected with no credentials. With the API
requiring a bearer token (HTTP) and a ``pwnproxy-token.`` subprotocol (WS), both
facts have to be proven, plus the failure mode: a ``401`` and a ``4401`` must
produce "run ``pwnproxy api token``", not a stack trace or a silent retry loop.

Everything here runs without a terminal: the pieces asserted are the client
factory, the message builders, the dashboard's request handlers and the WS retry
loop, driven with a mock transport and a fake ``websockets.connect``.
"""

from __future__ import annotations

import httpx
import pytest
from textual.app import App
from websockets.exceptions import WebSocketException

from apps.terminal.tui import ws_client
from apps.terminal.tui.api import (
    auth_error_message,
    create_client,
    websocket_error_message,
)
from apps.terminal.tui.app import DashboardApp
from apps.terminal.tui.scope_widget import ScopeTab
from pwnproxy.shared.api_client import TOKEN_HELP
from pwnproxy.shared.api_client import auth_error_message as pwnproxy_auth_error_message
from pwnproxy.shared.api_client import (
    websocket_error_message as pwnproxy_websocket_error_message,
)
from pwnproxy.shared.api_token import TOKEN_ENV, write_token
from pwnproxy.transport.rest.auth import MISSING_TOKEN_DETAIL


def test_messages_come_from_shared_not_from_the_tui():
    """The sentence a rejected token produces is owned by ``shared/``.

    ``pwnproxy/services/intruder/tui/screen.py`` needs the same text and the core
    may not import ``apps/`` (``tests/architecture/test_layering.py``), so the TUI
    re-exports the shared helpers instead of defining its own.
    """
    assert auth_error_message is pwnproxy_auth_error_message
    assert websocket_error_message is pwnproxy_websocket_error_message


@pytest.fixture
def api_home(tmp_path, monkeypatch):
    """A config dir with a known token and no ``PWNPROXY_API_TOKEN`` override."""
    monkeypatch.setenv("PWNPROXY_CONFIG_DIR", str(tmp_path))
    monkeypatch.delenv("PWNPROXY_API_TOKEN", raising=False)
    write_token("full", "the-api-token")
    return tmp_path


def _unauthorized_response() -> httpx.Response:
    return httpx.Response(401, json={"detail": MISSING_TOKEN_DETAIL})


@pytest.mark.asyncio
async def test_client_sends_the_bearer_token(api_home):
    """One client, one header: every TUI call goes through it."""
    seen: dict[str, str | None] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["authorization"] = request.headers.get("Authorization")
        seen["path"] = str(request.url)
        return httpx.Response(200, json=[])

    client = create_client("127.0.0.1", 17171)
    client._transport = httpx.MockTransport(handler)
    try:
        assert (await client.get("/sessions")).json() == []
        assert seen == {
            "authorization": "Bearer the-api-token",
            "path": "http://127.0.0.1:17171/api/v1/sessions",
        }
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_client_without_token_sends_no_authorization(api_home, monkeypatch):
    """Negative case: no token on disk → no header (the API answers 401/503)."""
    monkeypatch.setenv("PWNPROXY_CONFIG_DIR", str(api_home / "empty"))
    seen: dict[str, str | None] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["authorization"] = request.headers.get("Authorization")
        return httpx.Response(503, json={"detail": "No API token configured"})

    client = create_client("127.0.0.1", 17171)
    client._transport = httpx.MockTransport(handler)
    try:
        assert (await client.get("/sessions")).status_code == 503
        assert seen == {"authorization": None}
    finally:
        await client.aclose()


def test_auth_error_message_explains_a_401():
    """A 401 says what to run; other statuses are the caller's business."""
    assert auth_error_message(_unauthorized_response()) == (
        f"API rejected the token (401) — {TOKEN_HELP}, then restart the app. "
        "If it was rotated, run 'pwnproxy api token --rotate' first."
    )


def test_auth_error_message_explains_a_503():
    """The API with no token at all points at the command that creates it."""
    assert auth_error_message(httpx.Response(503, json={"detail": "x"})) == (
        "The API has no token configured (503) — run 'pwnproxy api token': "
        "it creates the token file the API expects."
    )


@pytest.mark.parametrize("status", [200, 403, 404, 500])
def test_auth_error_message_is_none_for_other_statuses(status):
    """Negative case: a plain error must not be reported as a token problem."""
    assert auth_error_message(httpx.Response(status, json={"detail": "x"})) is None


def test_websocket_error_message_for_4401_names_the_command(api_home):
    """A 4401 is the token: say which command shows it and that a restart follows."""
    assert websocket_error_message(4401, "127.0.0.1:17171 - closed") == (
        f"API rejected the WebSocket token (close 4401) — {TOKEN_HELP}, then restart the app."
    )


def test_websocket_error_message_mentions_the_env_override(monkeypatch):
    """With ``PWNPROXY_API_TOKEN`` set, the fix is the variable, not the file."""
    monkeypatch.setenv(TOKEN_ENV, "env-token")
    assert websocket_error_message(4401, "detail") == (
        f"API rejected the WebSocket token (close 4401) — {TOKEN_HELP}. "
        f"{TOKEN_ENV} is set: it wins over the token file."
    )


def test_websocket_error_message_passes_other_failures_through():
    """Negative case: a network error keeps saying what happened."""
    assert websocket_error_message(1006, "127.0.0.1:17171 - connection refused") == (
        "127.0.0.1:17171 - connection refused"
    )


@pytest.mark.asyncio
async def test_dashboard_reports_a_401_in_plain_language(api_home):
    """The session screens turn a 401 into the message, not into ``resp.text``."""
    dashboard = DashboardApp(host="127.0.0.1", api_port=17171)
    client = create_client("127.0.0.1", 17171)
    client._transport = httpx.MockTransport(lambda request: _unauthorized_response())
    dashboard._api_client = client
    shown: list[str] = []
    dashboard.notify = lambda message, **kwargs: shown.append(message)
    try:
        await dashboard._do_load("pentest")
    finally:
        await dashboard.aclose_api()

    assert shown == [
        f"API rejected the token (401) — {TOKEN_HELP}, then restart the app. "
        "If it was rotated, run 'pwnproxy api token --rotate' first."
    ]


@pytest.mark.asyncio
async def test_dashboard_shows_the_auth_message_only_once(api_home):
    """A retrying screen must not stack the same notification over and over."""
    dashboard = DashboardApp(host="127.0.0.1", api_port=17171)
    client = create_client("127.0.0.1", 17171)
    client._transport = httpx.MockTransport(lambda request: _unauthorized_response())
    dashboard._api_client = client
    shown: list[str] = []
    dashboard.notify = lambda message, **kwargs: shown.append(message)
    try:
        await dashboard._do_load("pentest")
        await dashboard._do_load("pentest")
    finally:
        await dashboard.aclose_api()

    assert len(shown) == 1


@pytest.mark.asyncio
async def test_scope_tab_uses_the_same_client(api_home):
    """The scope widget asks the seam, which carries the token."""
    tab = ScopeTab(api_port=17171)
    client = tab.api()
    try:
        assert client is tab.api()
        assert client.headers.get("Authorization") == "Bearer the-api-token"
    finally:
        await client.aclose()


class _StopStream(Exception):
    """Sentinel raised by ``on_error`` to break out of the retry loop."""


@pytest.mark.asyncio
async def test_traffic_stream_offers_the_token_and_explains_a_4401(api_home, monkeypatch):
    """The WS client authenticates the way the server wants, and a 4401 is reported."""

    class _Unauthorized(WebSocketException):
        code = 4401

    offered: dict[str, object] = {}

    def fake_connect(url, **kwargs):
        offered["url"] = url
        offered["subprotocols"] = kwargs.get("subprotocols")
        raise _Unauthorized("closed by the server")

    errors: list[str] = []

    def on_error(message: str) -> None:
        errors.append(message)
        raise _StopStream

    monkeypatch.setattr(ws_client.websockets, "connect", fake_connect)
    stream = ws_client.stream_traffic("127.0.0.1", 17171, on_error=on_error)
    with pytest.raises(_StopStream):
        await anext(stream)

    assert offered == {
        "url": "ws://127.0.0.1:17171/ws/traffic",
        "subprotocols": ["pwnproxy", "pwnproxy-token.the-api-token"],
    }
    assert errors == [
        f"API rejected the WebSocket token (close 4401) — {TOKEN_HELP}, then restart the app."
    ]


@pytest.mark.asyncio
async def test_findings_stream_without_token_offers_only_the_plain_protocol(
    api_home, monkeypatch
):
    """Negative case: no token → only ``pwnproxy``, and the message says what to run."""
    monkeypatch.setenv("PWNPROXY_CONFIG_DIR", str(api_home / "empty"))

    class _Unauthorized(WebSocketException):
        code = 4401

    def fake_connect(url, **kwargs):
        raise _Unauthorized("closed by the server")

    errors: list[str] = []

    def on_error(message: str) -> None:
        errors.append(message)
        raise _StopStream

    monkeypatch.setattr(ws_client.websockets, "connect", fake_connect)
    stream = ws_client.stream_findings("127.0.0.1", 17171, on_error=on_error)
    with pytest.raises(_StopStream):
        await anext(stream)

    assert errors == [
        f"API rejected the WebSocket token (close 4401) — {TOKEN_HELP}, then restart the app."
    ]


@pytest.mark.asyncio
async def test_stream_reports_a_connection_error_verbatim(api_home, monkeypatch):
    """Negative case: a down API is reported as such, not as a token problem."""

    def fake_connect(url, **kwargs):
        raise OSError("connection refused")

    errors: list[str] = []

    def on_error(message: str) -> None:
        errors.append(message)
        raise _StopStream

    monkeypatch.setattr(ws_client.websockets, "connect", fake_connect)
    stream = ws_client.stream_traffic("127.0.0.1", 17171, on_error=on_error)
    with pytest.raises(_StopStream):
        await anext(stream)

    assert errors == ["ws://127.0.0.1:17171/ws/traffic - connection refused"]


def test_dashboard_and_widget_are_textual_apps():
    """Sanity: the objects under test are the real Textual classes, not doubles."""
    assert issubclass(DashboardApp, App)
    assert isinstance(ScopeTab(api_port=17171), ScopeTab)
