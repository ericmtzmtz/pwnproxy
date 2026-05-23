import asyncio
from pathlib import Path

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
    from pwnproxy.cli.findings import _list_findings
    with patch("pwnproxy.cli.findings.Path.home", return_value=findings_dir):
        asyncio.run(_list_findings(None, 20))


def test_findings_filter_sqli(findings_dir):
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{findings_dir / '.pwnproxy' / 'scanner_results.db'}"
    )
    asyncio.run(_create_and_seed(engine))
    asyncio.run(engine.dispose())

    from unittest.mock import patch
    from pwnproxy.cli.findings import _list_findings
    with patch("pwnproxy.cli.findings.Path.home", return_value=findings_dir):
        asyncio.run(_list_findings("sqli", 20))


def test_findings_unknown_scanner():
    from typer.testing import CliRunner
    from pwnproxy.cli import app
    runner = CliRunner()
    result = runner.invoke(app, ["findings", "--scanner", "unknown"])
    assert result.exit_code != 0
    assert "unknown" in result.output.lower()


def test_findings_empty(findings_dir):
    from unittest.mock import patch
    from pwnproxy.cli.findings import _list_findings
    with patch("pwnproxy.cli.findings.Path.home", return_value=findings_dir):
        asyncio.run(_list_findings("sqli", 20))
