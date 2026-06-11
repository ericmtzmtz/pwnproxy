#!/usr/bin/env bash
# dev.sh — Start all pwnproxy services for local development
# Requires: poetry, node, pwnproxy on PATH
set -euo pipefail

PROXY_PORT="${PWNPROXY_PROXY_PORT:-8080}"
API_PORT="${PWNPROXY_API_PORT:-8000}"
WEB_PORT=4321
HEALTH_URL="http://127.0.0.1:${API_PORT}/api/v1/health"

# ── Prerequisites ──────────────────────────────────────────────
for cmd in poetry node pwnproxy; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "[ERROR] '$cmd' not found on PATH. Install it first." >&2
        exit 1
    fi
done

echo ""
echo "[dev] Starting pwnproxy dev environment..."

# ── Cleanup handler ────────────────────────────────────────────
cleanup() {
    echo ""
    echo "[dev] Shutting down..."
    kill 0 2>/dev/null || true
    wait
}
trap cleanup EXIT INT TERM

# ── Start Proxy ────────────────────────────────────────────────
echo "[dev] Starting proxy on port ${PROXY_PORT}..."
pwnproxy start --proxy-port "$PROXY_PORT" --api-port "$API_PORT" &
PROXY_PID=$!

# ── Poll health endpoint ───────────────────────────────────────
echo "[dev] Waiting for API to be ready..."
ready=false
for i in $(seq 1 5); do
    sleep 1
    if curl -sf "$HEALTH_URL" >/dev/null 2>&1; then
        ready=true
        break
    fi
    echo "  Attempt $i/5 — not ready yet..."
done

if [ "$ready" != "true" ]; then
    echo "[ERROR] API did not start within 5 seconds. Check the proxy process." >&2
    kill $PROXY_PID 2>/dev/null || true
    exit 1
fi

echo "[dev] API is ready!"

# ── Start Web UI ───────────────────────────────────────────────
echo "[dev] Starting Web UI on port ${WEB_PORT}..."
export PUBLIC_API_BASE="http://127.0.0.1:${API_PORT}/api/v1"

# ── Print URLs ─────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════╗"
echo "║        pwnproxy — Dev Environment   ║"
echo "╠══════════════════════════════════════╣"
echo "║  Proxy → http://127.0.0.1:${PROXY_PORT}            ║"
echo "║  API   → http://127.0.0.1:${API_PORT}              ║"
echo "║  Docs  → http://127.0.0.1:${API_PORT}/docs         ║"
echo "║  Web UI → http://127.0.0.1:${WEB_PORT}             ║"
echo "╚══════════════════════════════════════╝"
echo ""
echo "Press Ctrl+C to stop all services"
echo ""

# Start Web UI in foreground (blocks until Ctrl+C)
cd "$(dirname "$0")/web-ui"
npm run dev
