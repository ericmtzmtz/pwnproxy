"""``POST /api/v1/findings``: an external producer publishing a finding.

The endpoint exists so a plugin (or the premium UI) does not have to write the
session database itself: it validates, persists through ``FindingStorage`` (the
same path a scanner finding takes, triage callback included) and only then
publishes the ``finding`` event the WebSocket handlers forward.

Every rule in the spec has its negative case here: unknown field, wrong
vocabulary, oversized evidence, unknown scanner, no session, storage failure.
"""

import asyncio
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import create_async_engine

from pwnproxy.plugins.core.loader import PluginLoader
from pwnproxy.shared.findings.storage import FindingStorage
from pwnproxy.shared.hooks import HookBus
from pwnproxy.transport.rest.app import app

#: A full, valid body; ``payload``/``evidence`` are the only long free-text ones.
VALID_BODY = {
    "scanner": "sqli",
    "url": "https://target.local/item?id=1",
    "method": "get",
    "param_name": "id",
    "param_location": "query",
    "technique": "error-based",
    "severity": "high",
    "confidence": "confirmed",
    "payload": "' OR 1=1-- -",
    "evidence": "SQL syntax error in the response body",
}


@pytest.fixture
def api(monkeypatch):
    """Mount a real loader, a real findings table and a mock session manager."""
    hook_bus = HookBus()
    saved: list[dict] = []

    async def _on_saved(row: dict) -> None:
        saved.append(row)

    monkeypatch.setattr(FindingStorage, "on_saved", staticmethod(_on_saved))

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        scanner_engine = create_async_engine(
            f"sqlite+aiosqlite:///{Path(tmp) / 'scanner_results.db'}"
        )
        asyncio.run(FindingStorage(scanner_engine).create_table())

        loader = PluginLoader(hook_bus)
        asyncio.run(loader.refresh_catalog())

        session_mgr = MagicMock()
        session_mgr.active_name = "session-7"
        session_mgr.get_scanner_engine.return_value = scanner_engine

        app.state.hook_bus = hook_bus
        app.state.plugin_loader = loader
        app.state.session_manager = session_mgr

        with TestClient(app) as client:
            yield client, scanner_engine, saved, loader

        asyncio.run(scanner_engine.dispose())
        for attribute in ("hook_bus", "plugin_loader", "session_manager"):
            delattr(app.state, attribute)


def _rows(engine) -> list[dict]:
    """Read the session's ``findings`` table through the ORM (typed columns)."""
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.orm import sessionmaker

    from pwnproxy.shared.findings.storage import FindingORM

    async def _read():
        factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with factory() as session:
            result = await session.execute(select(FindingORM).order_by(FindingORM.id))
            return [
                {c.name: getattr(row, c.name) for c in FindingORM.__table__.columns}
                for row in result.scalars().all()
            ]

    return asyncio.run(_read())


def test_a_valid_finding_is_persisted_and_returned(api):
    client, engine, _, _ = api

    response = client.post("/api/v1/findings", json=VALID_BODY)

    assert (response.status_code, response.json()) == (
        201,
        {"id": 1, "scanner": "sqli", "session_id": "session-7"},
    )
    rows = _rows(engine)
    assert [
        (
            row["id"],
            row["scanner"],
            row["url"],
            row["method"],
            row["param_name"],
            row["param_location"],
            row["technique"],
            row["severity"],
            row["confidence"],
            row["payload"],
            row["evidence"],
            row["extra"],
            row["request_data"],
        )
        for row in rows
    ] == [
        (
            1,
            "sqli",
            "https://target.local/item?id=1",
            "GET",  # ``get`` normalised
            "id",
            "query",
            "error-based",
            "high",
            "confirmed",
            "' OR 1=1-- -",
            "SQL syntax error in the response body",
            {},
            None,
        )
    ]


def test_the_optional_fields_are_stored_when_present(api):
    client, engine, _, _ = api
    body = {
        **VALID_BODY,
        "param_location": "path",
        "timestamp": "2026-01-02T03:04:05+00:00",
        "extra": {"dbms": "postgres"},
        "request_data": {"headers": {"host": "target.local"}},
    }

    response = client.post("/api/v1/findings", json=body)

    row = _rows(engine)[0]
    assert (response.status_code, row["param_location"], row["extra"], row["request_data"]) == (
        201,
        "path",
        {"dbms": "postgres"},
        {"headers": {"host": "target.local"}},
    )


def test_the_findings_endpoint_returns_the_stored_location(api):
    client, _, _, _ = api
    body = {**VALID_BODY, "param_location": "path"}

    assert client.post("/api/v1/findings", json=body).status_code == 201
    listed = client.get("/api/v1/findings/sqli").json()

    assert (listed["total"], [item["param_location"] for item in listed["items"]]) == (1, ["path"])


def test_two_identical_posts_create_two_findings(api):
    client, _, _, _ = api

    first = client.post("/api/v1/findings", json=VALID_BODY)
    second = client.post("/api/v1/findings", json=VALID_BODY)

    assert (first.status_code, second.status_code, first.json()["id"] != second.json()["id"]) == (
        201,
        201,
        True,
    )


def test_an_installed_but_disabled_plugin_may_publish(api, install_fake_plugin):
    client, engine, _, loader = api
    fake = install_fake_plugin()
    # The fake distribution is installed after the fixture refreshed the catalog.
    asyncio.run(loader.refresh_catalog())

    response = client.post("/api/v1/findings", json={**VALID_BODY, "scanner": fake.plugin_name})

    assert (response.status_code, response.json()["scanner"], len(_rows(engine))) == (
        201,
        fake.plugin_name,
        1,
    )


@pytest.mark.parametrize(
    "override",
    [
        pytest.param({"technique": None}, id="missing-required-field"),
        pytest.param({"severity": "urgent"}, id="severity-vocabulary"),
        pytest.param({"confidence": "probable"}, id="confidence-vocabulary"),
        pytest.param({"evidence": "x" * 65_537}, id="evidence-too-long"),
        pytest.param({"payload": "x" * 65_537}, id="payload-too-long"),
        pytest.param({"url": "x" * 8_193}, id="url-too-long"),
        pytest.param({"param_location": ""}, id="empty-param-location"),
        pytest.param({"param_location": "x" * 51}, id="param-location-too-long"),
        pytest.param({"method": "x" * 11}, id="method-too-long"),
        pytest.param({"unknown_field": 1}, id="unknown-field"),
        pytest.param({"extra": {"blob": "x" * 65_537}}, id="extra-too-large"),
    ],
)
def test_invalid_bodies_are_422_and_write_nothing(api, override):
    client, engine, _, _ = api
    body = {**VALID_BODY, **override}
    if override == {"technique": None}:
        body.pop("technique")

    response = client.post("/api/v1/findings", json=body)

    assert (response.status_code, _rows(engine)) == (422, [])


def test_an_unknown_scanner_is_422_with_the_name(api):
    client, engine, _, _ = api

    response = client.post("/api/v1/findings", json={**VALID_BODY, "scanner": "scanner-que-no-existe"})

    assert (response.status_code, response.json()["detail"], _rows(engine)) == (
        422,
        "unknown scanner 'scanner-que-no-existe': it is not in the plugin catalog "
        "(see GET /api/v1/plugins)",
        [],
    )


def test_without_a_session_it_is_409_and_writes_nothing(api):
    client, engine, _, _ = api
    app.state.session_manager.active_name = None

    response = client.post("/api/v1/findings", json=VALID_BODY)

    assert (response.status_code, response.json(), _rows(engine)) == (
        409,
        {"detail": "no active session"},
        [],
    )


def test_the_ws_handlers_receive_the_finding(api):
    client, _, _, _ = api

    with client.websocket_connect("/ws/findings") as findings_ws:
        with client.websocket_connect("/ws/events") as events_ws:
            assert client.post("/api/v1/findings", json=VALID_BODY).status_code == 201
            from_findings = findings_ws.receive_json()
            from_events = events_ws.receive_json()

    expected = ("finding", 1, "sqli", "session-7")
    assert (
        (from_findings["type"], from_findings["id"], from_findings["scanner"], from_findings["session_id"]),
        (from_events["type"], from_events["id"], from_events["scanner"], from_events["session_id"]),
    ) == (expected, expected)


def test_the_triage_callback_runs_for_a_published_finding(api):
    client, _, saved, _ = api

    assert client.post("/api/v1/findings", json=VALID_BODY).status_code == 201

    deadline = time.monotonic() + 5
    while not saved and time.monotonic() < deadline:
        time.sleep(0.02)
    assert [(row["id"], row["scanner"]) for row in saved] == [(1, "sqli")]


def test_a_storage_failure_is_500_and_publishes_no_event(api, monkeypatch):
    client, engine, saved, _ = api
    published: list[tuple[str, object]] = []
    monkeypatch.setattr(
        app.state.hook_bus, "publish", lambda channel, data: published.append((channel, data))
    )

    async def _drop():
        async with engine.begin() as conn:
            await conn.execute(text("DROP TABLE findings"))

    asyncio.run(_drop())

    response = client.post("/api/v1/findings", json=VALID_BODY)

    assert (
        response.status_code,
        response.json()["detail"].startswith("could not save finding:"),
        published,
        saved,
    ) == (500, True, [], [])
