import asyncio
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from pwnproxy.shared.db import Base, FlowRecord


async def _seed(engine):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        session.add(FlowRecord(
            method="GET", url="http://example.com/",
            request_headers={"Host": "example.com"}, request_body=None,
            status_code=200, response_headers={}, response_body=None,
            timestamp=datetime(2026, 1, 1),
        ))
        session.add(FlowRecord(
            method="POST", url="http://test.com/api",
            request_headers={"Content-Type": "application/json"},
            request_body=b'{"key": "value"}',
            status_code=201, response_headers={}, response_body=b'{"id": 1}',
            timestamp=datetime(2026, 1, 2),
        ))
        await session.commit()


def _make_engine(path: Path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{path}")
    asyncio.run(_seed(engine))
    return engine


@pytest.fixture
def traffic_dir(tmp_path):
    db_dir = tmp_path / ".pwnproxy"
    db_dir.mkdir(parents=True, exist_ok=True)
    return tmp_path


def test_history_list_no_db(traffic_dir):
    from apps.terminal.cli.history import _list_flows
    engine = _make_engine(traffic_dir / ".pwnproxy" / "traffic.db")
    with patch("pwnproxy.cli.history._get_engine", return_value=engine):
        asyncio.run(_list_flows(10))
    asyncio.run(engine.dispose())


def test_history_get_not_found(traffic_dir):
    import typer
    from apps.terminal.cli.history import _get_flow
    engine = _make_engine(traffic_dir / ".pwnproxy" / "traffic.db")
    with patch("pwnproxy.cli.history._get_engine", return_value=engine):
        with pytest.raises(typer.Exit):
            asyncio.run(_get_flow(999))
    asyncio.run(engine.dispose())


def test_history_list_with_data(traffic_dir):
    from apps.terminal.cli.history import _list_flows
    engine = _make_engine(traffic_dir / ".pwnproxy" / "traffic.db")
    with patch("pwnproxy.cli.history._get_engine", return_value=engine):
        asyncio.run(_list_flows(10))
    asyncio.run(engine.dispose())
