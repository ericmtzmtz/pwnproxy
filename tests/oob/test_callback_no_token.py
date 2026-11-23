"""The OOB callback must keep answering without a credential.

The change that put a bearer token in front of the API intentionally left the
OOB callback out: the HTTP client calling it is the **target being scanned**, and
it cannot know any token. This test runs a real ``aiohttp`` server on an
ephemeral port (never the dev port: ``dev.ps1`` owns ``17173`` here) and checks
the two sides of that decision:

* a valid canary returns ``200`` with no ``Authorization`` header and gets
  registered as confirmed;
* an unknown token is ``404`` — never ``401``, which would mean somebody put
  authentication in front of it.
"""

from __future__ import annotations

import asyncio

import httpx

from pwnproxy.shared.canary import get_registry
from pwnproxy.shared.http_server import HTTPCallbackServer


def _callback(canary_from: str | None) -> tuple[httpx.Response, bool]:
    """Hit the callback server once and report the answer and the canary state.

    The request goes through ``httpx.AsyncClient``: the server runs in the same
    event loop, so a blocking client would deadlock (it would wait for a reply
    that cannot be produced until it returns).
    """
    async def _run() -> tuple[httpx.Response, bool]:
        registry = get_registry()
        canary = registry.create("scan-oob")
        server = HTTPCallbackServer(host="127.0.0.1", port=0)
        await server.start()
        try:
            token = canary.token if canary_from is None else canary_from
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(server.get_callback_url(token))
        finally:
            await server.stop()
        return response, canary.callback_received

    return asyncio.run(_run())


def test_a_canary_is_confirmed_without_any_authorization_header():
    response, confirmed = _callback(None)

    assert (response.status_code, response.text, confirmed) == (200, "OK", True)


def test_an_unknown_token_is_404_not_401():
    response, _confirmed = _callback("token-que-no-existe")

    assert (response.status_code, response.headers.get("www-authenticate")) == (404, None)
