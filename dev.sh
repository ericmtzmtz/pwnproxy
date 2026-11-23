#!/usr/bin/env bash
# dev.sh — Start all pwnproxy services for local development
# Requires: node, and either poetry (repo virtualenv, preferred) or a pwnproxy
#           executable on PATH (fallback only)
#
#   ./dev.sh             — start dev environment
#
# pwnproxy always runs from the repo virtualenv when poetry + pyproject.toml are
# present. A global `pwnproxy` executable is only used as a fallback and is
# announced: a stale `pip install -e .` outside poetry has no dependencies
# (aiosqlite & co.), so it dies at import time.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${REPO_ROOT}/.dev-logs"
LOG_FILE="${LOG_DIR}/pwnproxy.log"

PROXY_PORT="${PWNPROXY_PROXY_PORT:-17170}"
API_PORT="${PWNPROXY_API_PORT:-17171}"
CALLBACK_PORT="${CALLBACK_PORT:-17173}"
WEB_PORT="${WEB_PORT:-17172}"
HEALTH_URL="http://127.0.0.1:${API_PORT}/api/v1/health"
API_BASE="http://127.0.0.1:${API_PORT}/api/v1"
MAX_ATTEMPTS=15
TAIL_LINES=25

# ── Output helpers (colours only on a terminal) ────────────────
yellow() { if [ -t 1 ]; then printf '\033[33m%s\033[0m\n' "$1"; else printf '%s\n' "$1"; fi; }
red()    { if [ -t 2 ]; then printf '\033[31m%s\033[0m\n' "$1" >&2; else printf '%s\n' "$1" >&2; fi; }
gray()   { if [ -t 1 ]; then printf '\033[90m%s\033[0m\n' "$1"; else printf '%s\n' "$1"; fi; }

# ── Prerequisites ──────────────────────────────────────────────
if ! command -v node >/dev/null 2>&1; then
    red "[ERROR] 'node' not found on PATH. Install it first."
    exit 1
fi

# ── Which pwnproxy to run: repo virtualenv first ───────────────
PWN_CMD=()
if [ -f "${REPO_ROOT}/pyproject.toml" ] && command -v poetry >/dev/null 2>&1; then
    PWN_CMD=(poetry run pwnproxy)
else
    if ! command -v pwnproxy >/dev/null 2>&1; then
        red "[ERROR] Could not find pwnproxy: poetry is not on PATH and no pwnproxy executable is available."
        yellow "  Recommended: run 'poetry install' in ${REPO_ROOT}, then retry."
        exit 1
    fi
    GLOBAL_PWN="$(command -v pwnproxy)"
    yellow "[dev] WARNING: using a GLOBAL pwnproxy executable (${GLOBAL_PWN}). Its dependencies may not match pyproject.toml (missing aiosqlite etc.)."
    PWN_CMD=("${GLOBAL_PWN}")
fi
gray "[dev] Using ${PWN_CMD[*]}"

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

# ── Log tail helper for a pwnproxy that died ───────────────────
print_log_tail() {
    if [ -s "$LOG_FILE" ]; then
        yellow "[dev] Last ${TAIL_LINES} line(s) of the log:"
        tail -n "$TAIL_LINES" "$LOG_FILE" | sed 's/^/  /'
    else
        gray "[dev] (no log output captured)"
    fi
    if grep -qiE 'Errno 10048|WinError 10048|address already in use|EADDRINUSE' "$LOG_FILE" 2>/dev/null; then
        yellow "  The log says the port is in use. Try: PWNPROXY_PROXY_PORT=9090 ./dev.sh"
    fi
    gray "[dev]   log: ${LOG_FILE}"
}

# ── Start Proxy ────────────────────────────────────────────────
mkdir -p "$LOG_DIR"
: > "$LOG_FILE"
echo "[dev] Starting proxy on port ${PROXY_PORT}..."
gray "[dev]   log: ${LOG_FILE}"
"${PWN_CMD[@]}" start --proxy-port "$PROXY_PORT" --api-port "$API_PORT" --callback-port "$CALLBACK_PORT" >>"$LOG_FILE" 2>&1 &
PROXY_PID=$!

# ── Poll health endpoint ───────────────────────────────────────
echo "[dev] Waiting for API to be ready..."
ready=false
exited=false
for i in $(seq 1 "$MAX_ATTEMPTS"); do
    sleep 1
    if ! kill -0 "$PROXY_PID" 2>/dev/null; then
        exited=true
        break
    fi
    if curl -sf "$HEALTH_URL" >/dev/null 2>&1; then
        ready=true
        break
    fi
    echo "  Attempt $i/${MAX_ATTEMPTS} - not ready yet..."
done

if [ "$exited" = "true" ]; then
    code=0
    wait "$PROXY_PID" 2>/dev/null || code=$?
    red "[ERROR] pwnproxy exited prematurely (exit code ${code})."
    print_log_tail
    exit 1
fi

if [ "$ready" != "true" ]; then
    red "[ERROR] API did not start within ${MAX_ATTEMPTS} seconds."
    print_log_tail
    kill "$PROXY_PID" 2>/dev/null || true
    exit 1
fi

echo "[dev] API is ready!"
gray "[dev]   log: ${LOG_FILE}"

# ── API token for the Web UI URL ───────────────────────────────
# The API requires Authorization: Bearer <token> and the Web UI takes it from
# the URL fragment. Only the URL is printed: the token must not show up on any
# other line (it would end up in a log or in a pasted issue).
WEB_UI_URL="http://127.0.0.1:${WEB_PORT}/"
API_TOKEN="$("${PWN_CMD[@]}" api token 2>/dev/null | sed -n 's/^Token:[[:space:]]*//p' | head -n 1)"
if [ -n "$API_TOKEN" ]; then
    WEB_UI_URL="http://127.0.0.1:${WEB_PORT}/#token=${API_TOKEN}"
else
    yellow "[dev] WARNING: could not read the API token; get it with: ${PWN_CMD[*]} api token"
fi

# ── Start Web UI ───────────────────────────────────────────────
echo "[dev] Starting Web UI on port ${WEB_PORT}..."
export PUBLIC_API_BASE="$API_BASE"

# ── Print URLs ─────────────────────────────────────────────────
echo ""
echo "--- pwnproxy Dev Environment ---"
echo "  API     -> http://127.0.0.1:${API_PORT}"
echo "  Proxy   -> http://127.0.0.1:${PROXY_PORT}"
echo "  Docs    -> http://127.0.0.1:${API_PORT}/docs"
echo "  Web UI  -> ${WEB_UI_URL}"
echo "             (open this URL: the token travels in the fragment, never to a server)"
echo "  Log     -> ${LOG_FILE}"
echo "-------------------------------"
echo ""
echo "Press Ctrl+C to stop all services"
echo ""

# Start Web UI in foreground (blocks until Ctrl+C)
cd "${REPO_ROOT}/apps/web"
npm run dev -- --host --port "$WEB_PORT"
