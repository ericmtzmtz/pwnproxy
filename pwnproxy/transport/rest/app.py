import os

from fastapi import FastAPI, Request
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import Response

from pwnproxy.shared.observability import gen_correlation_id, set_correlation_id
from pwnproxy.shared.ports import DEFAULT_WEB_PORT
from pwnproxy.transport.rest import (
    auth,
    crawler,
    docs,
    findings,
    health,
    interceptor,
    intruder,
    plugins,
    proxy,
    repeater,
    reports,
    scanners,
    session,
    tasks,
    tokens,
    traffic,
    workers,
)
from pwnproxy.transport.rest.auth import api_auth_middleware
from pwnproxy.transport.ws.events import router as ws_router

_ORIGINS_ENV = os.environ.get(
    "CORS_ORIGINS",
    f"http://localhost:{DEFAULT_WEB_PORT},http://127.0.0.1:{DEFAULT_WEB_PORT}",
)
ALLOWED_ORIGINS = [o.strip() for o in _ORIGINS_ENV.split(",") if o.strip()]

#: Headers the browser is allowed to send. ``*`` would also work, but the list
#: is the contract: ``Authorization`` has to be here or the Web UI's token never
#: leaves the browser.
ALLOWED_HEADERS = ["Authorization", "Content-Type", "X-Correlation-ID"]

#: Methods the API actually answers.
ALLOWED_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]

app = FastAPI(
    title="PwnProxy API",
    description="Control plane for pwnproxy - traffic, findings, sessions, interceptor, repeater, intruder, plugins, scan",
    version="0.1.0",
    # ``/docs`` is served by ``transport/rest/docs.py`` (schema embedded, no
    # ``fetch`` to the protected ``/openapi.json``); ``/redoc`` has no equivalent
    # and is disabled so it cannot serve the schema unauthorised.
    docs_url=None,
    redoc_url=None,
)

# Middleware order matters and the registration order is the *inverse* of the
# runtime order (each ``add_middleware`` inserts at position 0), so the result
# here is CORS → correlation → auth → routes:
#   * CORS outermost, so a 401/503 still carries ``Access-Control-Allow-Origin``
#     and the Web UI can read the status instead of seeing a network error.
#   * correlation next, so rejected requests also get ``X-Correlation-ID``.
#   * auth innermost, so it only sees requests CORS already accepted.
app.middleware("http")(api_auth_middleware)


@app.middleware("http")
async def correlation_middleware(request: Request, call_next):
    """Assign a correlation_id to every request and propagate via contextvar."""
    cid = request.headers.get("X-Correlation-ID") or gen_correlation_id()
    set_correlation_id(cid)
    response: Response = await call_next(request)
    response.headers["X-Correlation-ID"] = cid
    return response


app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    # No cookies are used: the credential is the ``Authorization`` header, so
    # credentialed CORS (and therefore ``*``-with-credentials) is not needed.
    allow_credentials=False,
    allow_methods=ALLOWED_METHODS,
    allow_headers=ALLOWED_HEADERS,
    expose_headers=["X-Correlation-ID"],
)

app.include_router(traffic)
app.include_router(findings)
app.include_router(session)
app.include_router(tokens)
app.include_router(interceptor)
app.include_router(repeater)
app.include_router(intruder)
app.include_router(scanners)
app.include_router(plugins)
app.include_router(ws_router)
app.include_router(tasks)
app.include_router(reports)
app.include_router(crawler)
app.include_router(proxy)
app.include_router(health)
app.include_router(workers)
app.include_router(auth)
app.include_router(docs)
