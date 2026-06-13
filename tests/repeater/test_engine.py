import pytest
from unittest.mock import AsyncMock, patch


@pytest.mark.asyncio
async def test_engine_send_with_mock():
    from pwnproxy.services.repeater.engine import RepeaterEngine

    engine = RepeaterEngine()

    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.headers = {"Content-Type": "application/json"}
    mock_response.content = b'{"ok": true}'
    mock_response.json = AsyncMock(return_value={"ok": True})

    with patch.object(engine, "_get_client") as mock_get_client:
        mock_client = AsyncMock()
        mock_client.request.return_value = mock_response
        mock_get_client.return_value = mock_client

        parsed = {
            "method": "GET",
            "path": "/api",
            "headers": {"Host": "example.com"},
            "body": "",
        }
        response = await engine.send(parsed)
        assert response.status_code == 200
        assert await response.json() == {"ok": True}
        mock_client.request.assert_called_once()

    await engine.close()
