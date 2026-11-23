"""Authentication of the local API: the token contract and its guards.

``specs/api-auth/spec.md`` is the contract and every requirement has its negative
case here: no header, wrong token, ``Basic`` instead of ``Bearer``, no token
configured at all, a WebSocket without the subprotocol, a token in the query
string, an ``agent`` token reaching a ``full`` route, ``/docs``/``/redoc``/
``/openapi.json``, CORS with a foreign origin.

Two of these tests are **guards** over the route table (``test_every_http_route…``
and ``test_every_websocket…``): they walk the app instead of listing routes, so a
route somebody adds later is either protected or the suite is red. Both were
proven red by mutating the code (adding a path to the exempt list / removing
``authorize_websocket`` from a handler) — see ``docs/sesiones/plataforma.md``.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
import uuid

import httpx
import pytest
import uvicorn
from fastapi.testclient import TestClient
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.routing import WebSocketRoute
from starlette.websockets import WebSocketDisconnect

from pwnproxy.shared.api_token import (
    SCOPE_AGENT,
    SCOPE_FULL,
    WS_SUBPROTOCOL,
    WS_TOKEN_PREFIX,
    WS_UNAUTHORIZED_CLOSE_CODE,
    rotate_token,
    write_token,
)
from pwnproxy.shared.hooks import HookBus
from pwnproxy.shared.ports import DEFAULT_WEB_PORT
from pwnproxy.transport.rest.app import app
from pwnproxy.transport.rest.auth import (
    AUTH_EXEMPT_PATHS,
    FORBIDDEN_SCOPE_DETAIL,
    MISSING_TOKEN_DETAIL,
    NO_TOKEN_DETAIL,
    WWW_AUTHENTICATE,
    require_scope,
)

#: Paths a client may use before it has a token, with the reason.
EXEMPT = {
    "/api/v1/health": "the dev/Docker probe, returns nothing sensitive",
    "/docs": "public API reference, schema embedded, no data",
}

MISSING_BODY = {"detail": MISSING_TOKEN_DETAIL}
NO_TOKEN_BODY = {"detail": NO_TOKEN_DETAIL}
FORBIDDEN_BODY = {"detail": FORBIDDEN_SCOPE_DETAIL}


@pytest.fixture
def raw_client():
    """A ``TestClient`` with **no** credentials: the only way to see a ``401``."""
    return TestClient(app)


@pytest.fixture
def tokens_in_config_dir(tmp_path, monkeypatch):
    """Move the token files to ``tmp_path`` and drop the env token."""
    monkeypatch.setenv("PWNPROXY_CONFIG_DIR", str(tmp_path))
    monkeypatch.delenv("PWNPROXY_API_TOKEN", raising=False)
    return tmp_path


@pytest.fixture
def hook_bus():
    """Give the app a bus so the WebSocket handlers can subscribe."""
    bus = HookBus()
    app.state.hook_bus = bus
    yield bus
    delattr(app.state, "hook_bus")


def _iter_routes(routes=None):
    """Yield every route of the app, descending into included routers.

    This FastAPI keeps ``include_router`` results as ``_IncludedRouter`` nodes
    without a ``path`` (they are resolved per request), so the naive
    ``for route in app.routes`` sees 19 nodes instead of 71. The nested router is
    reached through ``original_router`` — read with ``getattr`` so a rename in
    FastAPI fails loudly instead of silently checking nothing.
    """
    for route in app.routes if routes is None else routes:
        nested = getattr(route, "original_router", None)
        if nested is not None:
            yield from _iter_routes(nested.routes)
        else:
            yield route


def _concrete_path(path: str) -> str:
    return re.sub(r"\{[^}]+\}", str(uuid.uuid4()), path)


def _ws_close_code(client, url: str, subprotocols=None, timeout: float = 5.0):
    """Open ``url``, wait for the server to close, return the close code.

    ``WebSocketTestSession.receive_text`` blocks forever when the server does not
    close, so the read runs in a thread with a join timeout: a broken guard makes
    the assertion fail (``None``) instead of hanging the suite. Any other
    exception is returned as text so the failure message says what happened.
    """
    box: dict[str, object] = {}

    def _read() -> None:
        try:
            with client.websocket_connect(url, subprotocols=subprotocols) as ws:
                ws.receive_text()
        except WebSocketDisconnect as exc:
            box["code"] = exc.code
        except Exception as exc:  # reported, never swallowed
            box["error"] = exc

    thread = threading.Thread(target=_read, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        return f"no close within {timeout}s"
    if "error" in box:
        return repr(box["error"])
    return box.get("code")


class TestHttpToken:
    def test_no_header_is_401_with_the_fixed_body(self, raw_client):
        response = raw_client.get("/api/v1/flows")

        assert (
            response.status_code,
            response.json(),
            response.headers.get("www-authenticate"),
        ) == (401, MISSING_BODY, WWW_AUTHENTICATE)

    def test_a_wrong_token_is_401_and_the_handler_never_runs(self, raw_client):
        """No traffic engine is mounted: a 500 here would mean the route ran."""
        response = raw_client.delete("/api/v1/flows", headers={"Authorization": "Bearer token-inventado"})

        assert (response.status_code, response.json()) == (401, MISSING_BODY)

    def test_another_scheme_is_401_not_403(self, raw_client):
        response = raw_client.get("/api/v1/flows", headers={"Authorization": "Basic dXNlcjpwYXNz"})

        assert (response.status_code, response.json()) == (401, MISSING_BODY)

    def test_a_bearer_without_a_token_is_401(self, raw_client):
        response = raw_client.get("/api/v1/flows", headers={"Authorization": "Bearer "})

        assert (response.status_code, response.json()) == (401, MISSING_BODY)

    def test_health_is_public(self, raw_client):
        response = raw_client.get("/api/v1/health")

        assert (response.status_code, "checks" in response.json()) == (200, True)

    def test_the_401_does_not_echo_the_token(self, raw_client):
        sent = "abc123-do-not-echo-me"

        response = raw_client.get("/api/v1/flows", headers={"Authorization": f"Bearer {sent}"})

        assert (sent in response.text, sent in json.dumps(dict(response.headers))) == (False, False)

    def test_without_any_token_source_it_is_503(self, raw_client, tokens_in_config_dir):
        """Deleting the files must not turn the API into an open one."""
        response = raw_client.get("/api/v1/flows", headers={"Authorization": "Bearer whatever"})

        assert (response.status_code, response.json()) == (503, NO_TOKEN_BODY)

    def test_health_still_answers_without_any_token(self, raw_client, tokens_in_config_dir):
        assert raw_client.get("/api/v1/health").status_code == 200

    def test_the_exempt_list_is_exactly_the_two_documented_paths(self):
        assert set(EXEMPT) == AUTH_EXEMPT_PATHS


class TestWhoami:
    def test_the_full_token_reports_full(self, api_client):
        with api_client(app) as client:
            response = client.get("/api/v1/auth/whoami")

        assert (response.status_code, response.json()) == (200, {"scope": "full"})

    def test_the_mcp_token_reports_agent(self, tokens_in_config_dir):
        write_token(SCOPE_AGENT, "mcp-token-for-the-test")

        with TestClient(app, headers={"Authorization": "Bearer mcp-token-for-the-test"}) as client:
            response = client.get("/api/v1/auth/whoami")

        assert (response.status_code, response.json()) == (200, {"scope": "agent"})

    def test_whoami_without_a_token_is_401(self, raw_client):
        assert raw_client.get("/api/v1/auth/whoami").status_code == 401


class TestRequireScope:
    def _request(self, scope: str | None) -> Request:
        request = Request({"type": "http", "headers": []})
        if scope is not None:
            request.state.scope = scope
        return request

    def test_an_agent_token_is_403_with_a_fixed_message(self):
        from fastapi import HTTPException

        dependency = require_scope(SCOPE_FULL)

        with pytest.raises(HTTPException) as exc:
            dependency(self._request("agent"))

        assert (exc.value.status_code, exc.value.detail) == (403, FORBIDDEN_SCOPE_DETAIL)

    def test_a_full_token_passes(self):
        require_scope(SCOPE_FULL)(self._request("full"))

    def test_a_missing_scope_is_403_too(self):
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc:
            require_scope(SCOPE_FULL)(self._request(None))

        assert exc.value.status_code == 403


class TestScopeGuard:
    def test_every_http_route_requires_token(self):
        """Walk the whole route table: a new unprotected route breaks the suite.

        ``raise_server_exceptions=False`` so a route that *does* run answers
        ``500`` and the assertion reports the status instead of raising inside
        the client (no state is mounted on the app here, so any handler that
        executes fails).
        """
        client = TestClient(app, raise_server_exceptions=False)
        failures: dict[str, int] = {}
        checked = 0
        for route in _iter_routes():
            methods = getattr(route, "methods", None)
            if not methods or isinstance(route, WebSocketRoute):
                continue
            path = getattr(route, "path", None)
            if path in EXEMPT or path is None:
                continue
            url = _concrete_path(path)
            for method in sorted(methods - {"HEAD", "OPTIONS"}):
                checked += 1
                response = client.request(method, url)
                if response.status_code != 401:
                    failures[f"{method} {path}"] = response.status_code

        assert (failures, checked >= 60) == ({}, True)


class TestWebSocketToken:
    def test_every_websocket_closes_4401_without_the_subprotocol(self, raw_client):
        """Walk the WebSocket table: a handler without ``authorize_websocket`` fails."""
        failures: dict[str, object] = {}
        checked = 0
        for route in _iter_routes():
            if not isinstance(route, WebSocketRoute):
                continue
            checked += 1
            code = _ws_close_code(raw_client, _concrete_path(route.path))
            if code != WS_UNAUTHORIZED_CLOSE_CODE:
                failures[route.path] = code

        assert (failures, checked) == ({}, 4)

    @pytest.mark.parametrize(
        "path",
        ["/ws/traffic", "/ws/findings", "/ws/events", "/ws/rooms/traffic:demo"],
    )
    def test_a_missing_or_wrong_token_closes_4401(self, raw_client, path, hook_bus):
        missing = _ws_close_code(raw_client, path)
        wrong = _ws_close_code(raw_client, path, subprotocols=[WS_SUBPROTOCOL, f"{WS_TOKEN_PREFIX}no-existe"])

        assert (missing, wrong) == (WS_UNAUTHORIZED_CLOSE_CODE, WS_UNAUTHORIZED_CLOSE_CODE)

    def test_a_token_in_the_query_does_not_authenticate(self, raw_client, test_api_token):
        """The query ends up in access logs, so it is not a credential channel."""
        code = _ws_close_code(raw_client, f"/ws/findings?token={test_api_token}")

        assert code == WS_UNAUTHORIZED_CLOSE_CODE

    def test_the_subprotocol_is_answered_and_events_flow(self, api_client, hook_bus, test_api_token):
        subprotocols = [WS_SUBPROTOCOL, f"{WS_TOKEN_PREFIX}{test_api_token}"]

        with api_client(app) as client:
            with client.websocket_connect("/ws/events", subprotocols=subprotocols) as ws:
                negotiated = ws.accepted_subprotocol
                hook_bus.publish("scan.completed", {"task_id": "1", "session_id": "demo"})
                event = json.loads(ws.receive_text())

        assert (negotiated, event["type"], event["task_id"]) == (WS_SUBPROTOCOL, "scan.completed", "1")

    def test_the_room_keeps_its_own_error_codes_once_authenticated(self, api_client):
        """Auth comes first; the room scheme still answers 4404 with a valid token."""
        with api_client(app) as client:
            assert _ws_close_code(client, "/ws/rooms/badroom") == 4404


class TestCors:
    def _preflight(self, origin: str):
        return TestClient(app).options(
            "/api/v1/flows",
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "authorization",
            },
        )

    def test_the_allowed_origin_gets_the_headers(self):
        origin = f"http://127.0.0.1:{DEFAULT_WEB_PORT}"

        response = self._preflight(origin)

        assert (
            response.status_code,
            response.headers.get("access-control-allow-origin"),
            "Authorization" in response.headers.get("access-control-allow-headers", ""),
        ) == (200, origin, True)

    def test_a_foreign_origin_gets_no_allow_origin(self):
        response = self._preflight("http://evil.example")

        assert "access-control-allow-origin" not in response.headers

    def test_the_preflight_does_not_need_a_token(self):
        response = self._preflight(f"http://localhost:{DEFAULT_WEB_PORT}")

        assert response.status_code != 401

    def test_cors_does_not_replace_the_token(self, raw_client):
        response = raw_client.get("/api/v1/flows", headers={"Origin": f"http://127.0.0.1:{DEFAULT_WEB_PORT}"})

        assert (response.status_code, response.json()) == (401, MISSING_BODY)

    def test_the_policy_is_an_explicit_list_without_credentials(self):
        options = next(
            middleware.kwargs for middleware in app.user_middleware if middleware.cls is CORSMiddleware
        )

        assert (
            "*" in options["allow_origins"],
            options["allow_credentials"],
            options["allow_headers"],
            options["allow_methods"],
        ) == (False, False, ["Authorization", "Content-Type", "X-Correlation-ID"], [
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "OPTIONS",
        ])


class TestDocs:
    def test_openapi_json_requires_token(self, raw_client):
        assert raw_client.get("/openapi.json").status_code == 401

    def test_openapi_json_works_with_a_token(self, api_client):
        with api_client(app) as client:
            response = client.get("/openapi.json")

        assert (response.status_code, response.json()["openapi"].startswith("3.")) == (200, True)

    def test_docs_is_public_and_embeds_the_schema(self, raw_client):
        response = raw_client.get("/docs")

        assert (
            response.status_code,
            response.headers["content-type"].split(";")[0],
            '"openapi"' in response.text,
            "openapi.json" in response.text,
        ) == (200, "text/html", True, False)

    def test_redoc_is_not_served(self, raw_client):
        assert raw_client.get("/redoc").status_code in (401, 404)


class TestRotationEndToEnd:
    def test_rotation_invalidates_the_old_token_without_a_restart(self, tokens_in_config_dir):
        write_token(SCOPE_FULL, "the-first-token")
        client = TestClient(app)

        before = client.get("/api/v1/auth/whoami", headers={"Authorization": "Bearer the-first-token"})
        new_token = rotate_token(SCOPE_FULL)
        old_after = client.get("/api/v1/auth/whoami", headers={"Authorization": "Bearer the-first-token"})
        new_after = client.get("/api/v1/auth/whoami", headers={"Authorization": f"Bearer {new_token}"})

        assert (
            before.status_code,
            old_after.status_code,
            old_after.json(),
            new_after.status_code,
            new_after.json(),
        ) == (200, 401, MISSING_BODY, 200, {"scope": "full"})


class TestAccessLog:
    """The access log must never carry the token (it travels in a header).

    ``log_config=None`` keeps uvicorn from replacing the handlers, so the records
    land on the root logger and ``caplog`` sees them; the protocol of the request
    still has to be logged (a silently empty log would make the assertion
    vacuous), and the token — or its first 8 characters — must not appear.
    """

    def test_the_access_log_contains_no_part_of_the_token(self, test_api_token, caplog):
        access_logger = logging.getLogger("uvicorn.access")
        had_propagate = access_logger.propagate
        access_logger.propagate = True
        config = uvicorn.Config(
            app,
            host="127.0.0.1",
            port=0,
            log_level="info",
            access_log=True,
            log_config=None,
            lifespan="off",
        )
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, daemon=True)
        try:
            caplog.set_level(logging.INFO, logger="uvicorn.access")
            thread.start()
            deadline = time.monotonic() + 10
            while not server.started:
                assert time.monotonic() < deadline, "uvicorn did not start"
                time.sleep(0.05)
            port = server.servers[0].sockets[0].getsockname()[1]
            response = httpx.get(
                f"http://127.0.0.1:{port}/api/v1/auth/whoami",
                headers={"Authorization": f"Bearer {test_api_token}"},
                timeout=5,
            )
        finally:
            server.should_exit = True
            thread.join(timeout=10)
            access_logger.propagate = had_propagate

        records = [record.getMessage() for record in caplog.records if record.name == "uvicorn.access"]
        logged = "\n".join(records)
        assert (
            response.status_code,
            any("/api/v1/auth/whoami" in line for line in records),
            test_api_token in logged,
            test_api_token[:8] in logged,
        ) == (200, True, False, False)
