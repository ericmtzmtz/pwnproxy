"""Guard: every plugin-configuration route is in the scope matrix and needs a token.

Two ways to forget a rule are silent in a normal test suite: a new route that
nobody added to the matrix, and a route whose scope check was dropped while its
happy path still works. This file closes both:

* the table below is compared against ``plugin_config.router.routes`` — a route
  without a row (or a row without a route) fails the suite, so the next route has
  to make the decision explicit;
* every row is called with no token (``401``), with ``agent`` and with ``full``,
  and every write route is called with a secret body under both scopes: ``agent``
  must get the fixed ``403`` of the contract even though the rest of the body is
  valid.

Proven red by mutating the code (both restored): adding a path to
``AUTH_EXEMPT_PATHS`` and removing ``_check_secret_scope`` from the settings
route — see ``docs/sesiones/plataforma.md``.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient

from pwnproxy.plugins.core.config_schema import SECRET_WRITE_REQUIRES_FULL_DETAIL
from pwnproxy.transport.rest.app import app
from pwnproxy.transport.rest.auth import FORBIDDEN_SCOPE_DETAIL, MISSING_TOKEN_DETAIL

from ._plugin_config_fakes import CANARY, NAME, ConfigPlugin

#: The router module. ``from ... import plugin_config`` would give the router
#: itself (the package re-exports it), and the table must be checked against the
#: routes the router really holds.
router_module = importlib.import_module("pwnproxy.transport.rest.plugin_config")

#: Fixed ``403`` of a write that carries a secret field.
SECRET_WRITE_DETAIL = (
    "Secret fields can only be written with a token of scope 'full' (Web UI or CLI)"
)

#: Item the collection routes act on; the fake plugin is seeded with it.
ITEM = {"id": "app", "name": "app", "signing_key__set": False}


@dataclass(frozen=True)
class Row:
    """One route of the router, with what each scope must get.

    ``body`` is a request every scope may make; ``secret_body`` one that carries
    a declared secret and therefore separates ``agent`` (``403``) from ``full``.
    """

    method: str
    path: str
    agent: int
    full: int
    body: dict | None = None
    secret_body: dict | None = None
    secret_full: int = 0

    def url(self) -> str:
        """Concrete URL for the call (placeholders filled with real values)."""
        return self.path.format(
            name=NAME, collection="webhooks", item_id=ITEM["id"], action="ping"
        )


ROWS = [
    Row("GET", "/api/v1/plugins/{name}/schema", 200, 200),
    Row("GET", "/api/v1/plugins/{name}/settings", 200, 200),
    Row(
        "PATCH",
        "/api/v1/plugins/{name}/settings",
        200,
        200,
        body={"values": {"retries": 2}},
        secret_body={"values": {"signing_key": CANARY}},
        secret_full=200,
    ),
    Row("GET", "/api/v1/plugins/{name}/collections/{collection}", 200, 200),
    Row(
        "POST",
        "/api/v1/plugins/{name}/collections/{collection}",
        201,
        201,
        body={"values": {"name": "ci"}},
        secret_body={"values": {"name": "deploy", "signing_key": CANARY}},
        secret_full=201,
    ),
    Row(
        "PATCH",
        "/api/v1/plugins/{name}/collections/{collection}/{item_id}",
        200,
        200,
        body={"values": {"name": "app"}},
        secret_body={"values": {"signing_key": CANARY}},
        secret_full=200,
    ),
    Row("DELETE", "/api/v1/plugins/{name}/collections/{collection}/{item_id}", 204, 204),
    # ``ping`` requires ``full``: the route's matrix row is that pair.
    Row(
        "POST",
        "/api/v1/plugins/{name}/actions/{action}",
        403,
        200,
        body={"parameters": {"name": "app"}},
    ),
]

#: Only the rows whose route takes a secret.
SECRET_ROWS = [row for row in ROWS if row.secret_body is not None]

IDS = [f"{row.method} {row.path}" for row in ROWS]


@pytest.fixture
def raw_client():
    """A client with **no** credentials: the only way to see the ``401``."""
    return TestClient(app)


def _seeded(plugin_config, client=None):
    """Build a scene whose collection already holds :data:`ITEM`."""
    plugin = ConfigPlugin()
    plugin.items.append(dict(ITEM))
    return plugin_config(plugin, client=client)


def _send(client, row: Row, body: dict | None):
    """Call ``row`` with a JSON body only when the route takes one."""
    if body is None:
        return client.request(row.method, row.url())
    return client.request(row.method, row.url(), json=body)


class TestTheTableCoversTheRouter:
    def test_every_route_has_a_row_and_every_row_has_a_route(self):
        routes = {
            (method, route.path)
            for route in router_module.router.routes
            for method in route.methods
        }
        rows = {(row.method, row.path) for row in ROWS}

        assert (routes - rows, rows - routes) == (set(), set())


class TestEveryRouteNeedsAToken:
    @pytest.mark.parametrize("row", ROWS, ids=IDS)
    def test_without_a_token_it_is_401(self, raw_client, row):
        response = _send(raw_client, row, row.body)

        assert (response.status_code, response.json()) == (
            401,
            {"detail": MISSING_TOKEN_DETAIL},
        )


class TestTheScopeMatrix:
    @pytest.mark.parametrize("row", ROWS, ids=IDS)
    def test_full_gets_the_status_of_the_table(self, plugin_config, row):
        scene = _seeded(plugin_config)

        response = _send(scene.client, row, row.body)

        assert response.status_code == row.full

    @pytest.mark.parametrize("row", ROWS, ids=IDS)
    def test_agent_gets_the_status_of_the_table(self, plugin_config, agent_client, row):
        scene = _seeded(plugin_config, agent_client)

        response = _send(scene.client, row, row.body)

        assert response.status_code == row.agent

    @pytest.mark.parametrize("row", SECRET_ROWS, ids=lambda row: f"secret {row.method} {row.path}")
    def test_agent_never_writes_a_secret(self, plugin_config, agent_client, row):
        scene = _seeded(plugin_config, agent_client)

        response = _send(scene.client, row, row.secret_body)

        assert (
            response.status_code,
            response.json(),
            CANARY in response.text,
        ) == (403, {"detail": SECRET_WRITE_DETAIL}, False)

    @pytest.mark.parametrize("row", SECRET_ROWS, ids=lambda row: f"secret {row.method} {row.path}")
    def test_full_writes_the_secret_without_echoing_it(self, plugin_config, row):
        scene = _seeded(plugin_config)

        response = _send(scene.client, row, row.secret_body)

        assert (response.status_code, CANARY in response.text) == (row.secret_full, False)

    def test_a_secret_write_does_not_use_the_generic_scope_message(self):
        """Two different ``403``, on purpose (design D8): the client can act on one."""
        assert (
            SECRET_WRITE_DETAIL,
            SECRET_WRITE_DETAIL == FORBIDDEN_SCOPE_DETAIL,
        ) == (SECRET_WRITE_REQUIRES_FULL_DETAIL, False)
