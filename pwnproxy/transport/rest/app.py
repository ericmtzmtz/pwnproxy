import os

from fastapi import FastAPI, Request
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import Response

from pwnproxy.shared.observability import gen_correlation_id, set_correlation_id
from pwnproxy.transport.rest import crawler, findings, health, interceptor, intruder, plugins, proxy, repeater, reports, scanners, session, tasks, tokens, traffic
from pwnproxy.transport.ws.events import router as ws_router

_ORIGINS_ENV = os.environ.get("CORS_ORIGINS", "http://localhost:4321,http://127.0.0.1:4321,http://localhost:4322,http://127.0.0.1:4322")
ALLOWED_ORIGINS = [o.strip() for o in _ORIGINS_ENV.split(",") if o.strip()]

app = FastAPI(
    title="PwnProxy API",
    description="Control plane for pwnproxy - traffic, findings, sessions, interceptor, repeater, intruder, plugins, scan",
    version="0.1.0",
)


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
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
