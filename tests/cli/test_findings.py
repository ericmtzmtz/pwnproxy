import asyncio

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine


async def _create_and_seed(engine):
    async with engine.begin() as conn:
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS scan_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                method TEXT, url TEXT, param_name TEXT,
                param_location TEXT, technique TEXT,
                severity TEXT, confidence TEXT, payload TEXT,
                evidence TEXT, timestamp TEXT
            )
        """))
        await conn.execute(text("""
            INSERT INTO scan_findings
            (method, url, param_name, param_location, technique, severity, confidence, payload)
            VALUES ('GET', 'http://test.com?id=1', 'id', 'query',
                    'error-based', 'high', 'firm', \"' OR 1=1 --\")
        """))
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS xss_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                method TEXT, url TEXT, param_name TEXT,
                param_location TEXT, xss_type TEXT, context TEXT,
                severity TEXT, confidence TEXT, payload TEXT,
                evidence TEXT, timestamp TEXT
            )
        """))
        await conn.execute(text("""
            INSERT INTO xss_findings
            (method, url, param_name, param_location, xss_type, context, severity, confidence, payload)
            VALUES ('GET', 'http://test.com?q=foo', 'q', 'query',
                    'reflected', 'html-body', 'medium', 'tentative', '<script>alert(1)</script>')
        """))


@pytest.fixture
def findings_dir(tmp_path):
    db_dir = tmp_path / ".pwnproxy"
    db_dir.mkdir(parents=True, exist_ok=True)
    return tmp_path


def test_findings_all(findings_dir):
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{findings_dir / '.pwnproxy' / 'scanner_results.db'}"
    )
    asyncio.run(_create_and_seed(engine))
    asyncio.run(engine.dispose())

    from unittest.mock import patch

    from apps.terminal.cli.findings import _list_findings
    with patch("apps.terminal.cli.findings.Path.home", return_value=findings_dir):
        asyncio.run(_list_findings(None, 20))


def test_findings_filter_sqli(findings_dir):
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{findings_dir / '.pwnproxy' / 'scanner_results.db'}"
    )
    asyncio.run(_create_and_seed(engine))
    asyncio.run(engine.dispose())

    from unittest.mock import patch

    from apps.terminal.cli.findings import _list_findings
    with patch("apps.terminal.cli.findings.Path.home", return_value=findings_dir):
        asyncio.run(_list_findings("sqli", 20))


def test_findings_unknown_scanner_does_not_abort(findings_dir):
    """``--scanner`` is free text: the names come from the catalog, not from here.

    The old behaviour exited with an error against a hardcoded list of five
    scanners, which made every third-party finding unfilterable. An unknown name
    now just finds nothing and points at the scanners the database does have.
    """
    from unittest.mock import patch

    from pwnproxy.plugins.core.base import Finding
    from pwnproxy.shared.findings.storage import FindingStorage

    engine = create_async_engine(
        f"sqlite+aiosqlite:///{findings_dir / '.pwnproxy' / 'scanner_results.db'}"
    )

    async def _seed():
        storage = FindingStorage(engine)
        await storage.create_table()
        await storage.save(
            Finding(
                scanner="sqli",
                url="http://test.com?id=1",
                method="GET",
                param_name="id",
                param_location="query",
                technique="error-based",
                severity="high",
                confidence="confirmed",
                payload="1=1",
                evidence="error in response",
            )
        )

    asyncio.run(_seed())
    asyncio.run(engine.dispose())

    from typer.testing import CliRunner

    from apps.terminal.cli import app

    with patch("apps.terminal.cli.findings.Path.home", return_value=findings_dir):
        result = CliRunner().invoke(app, ["findings", "--scanner", "unknown"])

    assert (
        result.exit_code,
        "No findings for scanner: unknown" in result.output,
        "Scanners present in this database: sqli" in result.output,
    ) == (0, True, True)


def test_findings_empty(findings_dir):
    from unittest.mock import patch

    from apps.terminal.cli.findings import _list_findings
    with patch("apps.terminal.cli.findings.Path.home", return_value=findings_dir):
        asyncio.run(_list_findings("sqli", 20))
