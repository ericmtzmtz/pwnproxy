from fastapi import FastAPI

from pwnproxy.api.routers import findings, interceptor, intruder, repeater, scanners, session, tokens, traffic, ws

app = FastAPI(
    title="PwnProxy API",
    description="Control plane for pwnproxy - traffic, findings, sessions, interceptor, repeater, intruder",
    version="0.1.0",
)

app.include_router(traffic.router)
app.include_router(findings.router)
app.include_router(session.router)
app.include_router(tokens.router)
app.include_router(interceptor.router)
app.include_router(repeater.router)
app.include_router(intruder.router)
app.include_router(scanners.router)
app.include_router(ws.router)
