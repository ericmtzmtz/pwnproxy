"""``/docs``: the API reference page, with the schema embedded and no token.

FastAPI's stock ``/docs`` loads ``/openapi.json`` with ``fetch``, and the browser
cannot put an ``Authorization`` header on that request — so protecting the JSON
(the schema lists every route and every field) would leave the page broken. The
two options that do work are "turn ``/docs`` off" and "embed the schema":

* the page itself is **public**: it holds no data beyond the route list, which
  is public anyway (the API is AGPL),
* ``/openapi.json`` stays protected for tooling (``curl -H … | jq``),
* ``/redoc`` is disabled (``redoc_url=None``): it would have the same problem
  with none of the benefits.

The page takes the token from the URL fragment (``#token=…``) for "Try it out".
The fragment never reaches the server, so the token is not in any access log.
That the Swagger UI interceptor actually runs is a browser behaviour, verified
by hand and noted in ``docs/sesiones/plataforma.md``; the tests here check the
embedded schema and the absence of a ``/openapi.json`` call, not a browser.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

router = APIRouter(tags=["docs"])

#: Key the page uses for the token in ``localStorage`` (same as the Web UI).
TOKEN_STORAGE_KEY = "pwnproxy.api.token"

_DOCS_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PwnProxy API</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
  <style>
    body { margin: 0; background: #fafafa; }
    .pwnproxy-token { font-family: ui-monospace, monospace; padding: 12px 20px; background: #111827;
                      color: #e5e7eb; font-size: 13px; }
    .pwnproxy-token a { color: #7dd3fc; }
  </style>
</head>
<body>
  <div class="pwnproxy-token">
    Requests are authenticated with <code>Authorization: Bearer &lt;token&gt;</code>.
    Open this page as <code>/docs#token=&lt;token&gt;</code> (the token from
    <code>pwnproxy api token</code>) and "Try it out" works.
  </div>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    const SCHEMA = __SCHEMA__;
    const STORAGE_KEY = "__STORAGE_KEY__";

    function tokenFromFragment() {
      const match = /(?:^#|&)token=([^&]+)/.exec(window.location.hash || "");
      return match ? decodeURIComponent(match[1]) : "";
    }

    function currentToken() {
      try {
        return tokenFromFragment() || window.localStorage.getItem(STORAGE_KEY) || "";
      } catch (err) {
        return tokenFromFragment();
      }
    }

    window.ui = SwaggerUIBundle({
      spec: SCHEMA,
      dom_id: "#swagger-ui",
      deepLinking: true,
      requestInterceptor: function (request) {
        const token = currentToken();
        if (token) {
          request.headers = request.headers || {};
          request.headers["Authorization"] = "Bearer " + token;
        }
        return request;
      },
    });
  </script>
</body>
</html>
"""


def render_docs_html(schema: dict[str, Any]) -> str:
    """Return the ``/docs`` page with ``schema`` embedded in its JavaScript.

    Args:
        schema: Result of ``app.openapi()``.

    Returns:
        A self-contained HTML page (the only external references are the Swagger
        UI CDN assets). The schema is inlined, so the page issues no request for
        it — that is what lets ``/openapi.json`` require a token.
    """
    embedded = json.dumps(schema, ensure_ascii=False).replace("</", "<\\/")
    return (
        _DOCS_TEMPLATE.replace("__SCHEMA__", embedded)
        .replace("__STORAGE_KEY__", TOKEN_STORAGE_KEY)
    )


@router.get(
    "/docs",
    include_in_schema=False,
    response_class=HTMLResponse,
    summary="API reference (public, schema embedded)",
)
async def docs(request: Request) -> HTMLResponse:
    """Serve the API reference page built from this app's OpenAPI schema."""
    return HTMLResponse(render_docs_html(request.app.openapi()))
