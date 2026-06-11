import os

from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from pwnproxy.api.routers import findings, health, interceptor, intruder, plugins, proxy, repeater, scanners, session, tasks, tokens, traffic, ws

_ORIGINS_ENV = os.environ.get("CORS_ORIGINS", "http://localhost:4321,http://127.0.0.1:4321")
ALLOWED_ORIGINS = [o.strip() for o in _ORIGINS_ENV.split(",") if o.strip()]

app = FastAPI(
    title="PwnProxy API",
    description="Control plane for pwnproxy - traffic, findings, sessions, interceptor, repeater, intruder, plugins, scan",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(traffic.router)
app.include_router(findings.router)
app.include_router(session.router)
app.include_router(tokens.router)
app.include_router(interceptor.router)
app.include_router(repeater.router)
app.include_router(intruder.router)
app.include_router(scanners.router)
app.include_router(plugins.router)
app.include_router(ws.router)
app.include_router(tasks.router)
app.include_router(proxy.router)
app.include_router(health.router)
