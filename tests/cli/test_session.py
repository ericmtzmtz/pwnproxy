import asyncio
from pathlib import Path

import pytest

from pwnproxy.modules.session_manager.storage import TokenStorage
from pwnproxy.modules.session_manager.models import TokenCandidate


async def _seed(db_path: Path):
    storage = TokenStorage(db_path=str(db_path))
    await storage.init()
    candidates = [
        TokenCandidate(
            token_type="jwt",
            token_value="eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.test",
            label="admin jwt",
            status="valid",
            source_url="http://test.com/login",
        ),
        TokenCandidate(
            token_type="cookie",
            token_value="session=abc123",
            label="session cookie",
            status="unknown",
            source_url="http://test.com/",
        ),
    ]
    await storage.save(candidates)
    await storage.close()


@pytest.fixture
def session_dir(tmp_path):
    db_dir = tmp_path / ".pwnproxy"
    db_dir.mkdir(parents=True, exist_ok=True)
    return tmp_path


def test_session_list(session_dir):
    db_path = session_dir / ".pwnproxy" / "sessions.db"
    asyncio.run(_seed(db_path))

    from unittest.mock import patch
    from pwnproxy.cli.session import _list_sessions
    with patch("pwnproxy.modules.session_manager.storage.Path.home", return_value=session_dir):
        asyncio.run(_list_sessions(None))


def test_session_list_filtered(session_dir):
    db_path = session_dir / ".pwnproxy" / "sessions.db"
    asyncio.run(_seed(db_path))

    from unittest.mock import patch
    from pwnproxy.cli.session import _list_sessions
    with patch("pwnproxy.modules.session_manager.storage.Path.home", return_value=session_dir):
        asyncio.run(_list_sessions("jwt"))


def test_session_get_found(session_dir):
    db_path = session_dir / ".pwnproxy" / "sessions.db"
    asyncio.run(_seed(db_path))

    from unittest.mock import patch
    from pwnproxy.cli.session import _get_session
    with patch("pwnproxy.modules.session_manager.storage.Path.home", return_value=session_dir):
        asyncio.run(_get_session(1))


def test_session_get_not_found(session_dir):
    import typer
    from unittest.mock import patch
    from pwnproxy.cli.session import _get_session
    with patch("pwnproxy.modules.session_manager.storage.Path.home", return_value=session_dir):
        with pytest.raises(typer.Exit):
            asyncio.run(_get_session(999))


def test_session_delete_found(session_dir):
    db_path = session_dir / ".pwnproxy" / "sessions.db"
    asyncio.run(_seed(db_path))

    from unittest.mock import patch
    from pwnproxy.cli.session import _delete_session
    with patch("pwnproxy.modules.session_manager.storage.Path.home", return_value=session_dir):
        asyncio.run(_delete_session(1))


def test_session_delete_not_found(session_dir):
    import typer
    from unittest.mock import patch
    from pwnproxy.cli.session import _delete_session
    with patch("pwnproxy.modules.session_manager.storage.Path.home", return_value=session_dir):
        with pytest.raises(typer.Exit):
            asyncio.run(_delete_session(999))
