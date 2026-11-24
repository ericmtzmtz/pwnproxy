#!/usr/bin/env bash
# dev.sh — Start all pwnproxy services for local development
# Requires: node, and either poetry (repo virtualenv, preferred) or a pwnproxy
#           executable on PATH (fallback only)
#
#   ./dev.sh             — start dev environment
#
# The Web UI runs in the background and the box with the URL is printed only
# after it answers on its own port, so the printed link works on the first
# click instead of showing a connection error for ~15 s. PWNPROXY_WEBUI_TIMEOUT
# overrides the 60 s wait.
#
# pwnproxy always runs from the repo virtualenv when poetry + pyproject.toml are
# present. A global `pwnproxy` executable is only used as a fallback and is
# announced: a stale `pip install -e .` outside poetry has no dependencies
# (aiosqlite & co.), so it dies at import time.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${REPO_ROOT}/.dev-logs"
LOG_FILE="${LOG_DIR}/pwnproxy.log"
WEB_LOG="${LOG_DIR}/webui.log"

PROXY_PORT="${PWNPROXY_PROXY_PORT:-17170}"
API_PORT="${PWNPROXY_API_PORT:-17171}"
CALLBACK_PORT="${CALLBACK_PORT:-17173}"
WEB_PORT="${WEB_PORT:-17172}"
HEALTH_URL="http://127.0.0.1:${API_PORT}/api/v1/health"
API_BASE="http://127.0.0.1:${API_PORT}/api/v1"
WEB_PROBE_URL="http://127.0.0.1:${WEB_PORT}/"
MAX_ATTEMPTS=15
WEB_WAIT_TIMEOUT="${PWNPROXY_WEBUI_TIMEOUT:-60}"
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

# PWNPROXY_WEBUI_TIMEOUT must be a positive number of seconds.
case "$WEB_WAIT_TIMEOUT" in
    ''|*[!0-9]*|0)
        gray "[dev] WARNING: PWNPROXY_WEBUI_TIMEOUT='${WEB_WAIT_TIMEOUT}' is not a positive number; using 60."
        WEB_WAIT_TIMEOUT=60
        ;;
esac

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
# `kill 0` signals this whole process group, and the script is in it: without
# removing the traps first the handler re-enters itself (that used to loop and
# then dump core). INT/TERM are ignored while cleaning up so the group kill
# cannot cut the cleanup short.
cleanup() {
    local code=$?
    trap - EXIT INT TERM
    trap '' INT TERM
    echo ""
    echo "[dev] Shutting down..."
    for pid in "${TAIL_PID:-}" "${WEB_PID:-}" "${PROXY_PID:-}"; do
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    kill 0 2>/dev/null || true
    wait 2>/dev/null || true
    exit "$code"
}
trap cleanup EXIT INT TERM

# ── Log tail helper for a service that died ────────────────────
print_log_tail() {
    local path="${1:-$LOG_FILE}"
    if [ -s "$path" ]; then
        yellow "[dev] Last ${TAIL_LINES} line(s) of the log:"
        tail -n "$TAIL_LINES" "$path" | sed 's/^/  /'
    else
        gray "[dev] (no log output captured)"
    fi
    if [ "$path" = "$LOG_FILE" ] && grep -qiE 'Errno 10048|WinError 10048|address already in use|EADDRINUSE' "$path" 2>/dev/null; then
        yellow "  The log says the port is in use. Try: PWNPROXY_PROXY_PORT=9090 ./dev.sh"
    fi
    gray "[dev]   log: ${path}"
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
# other line (it would end up in a log or in a pasted issue), which is why the
# status line says OK/NOT FOUND instead of echoing the value.
WEB_UI_URL="http://127.0.0.1:${WEB_PORT}/"
API_TOKEN="$("${PWN_CMD[@]}" api token 2>/dev/null | sed -n 's/^Token:[[:space:]]*//p' | head -n 1 || true)"
if [ -n "$API_TOKEN" ]; then
    WEB_UI_URL="http://127.0.0.1:${WEB_PORT}/#token=${API_TOKEN}"
    echo "[dev] API token: OK"
else
    yellow "[dev] API token: NOT FOUND - the Web UI will ask for it (get it with: ${PWN_CMD[*]} api token)"
fi

# ── Start the Web UI in the background ─────────────────────────
# A background service must not take the console, so its output goes to a log
# (that log is also what the failure path tails) and is streamed below.
export PUBLIC_API_BASE="$API_BASE"
mkdir -p "$LOG_DIR"
: > "$WEB_LOG"
echo "[dev] Starting the Web UI on port ${WEB_PORT}..."
gray "[dev]   log: ${WEB_LOG}"
( cd "${REPO_ROOT}/apps/web" && exec npm run dev -- --host --port "$WEB_PORT" ) >>"$WEB_LOG" 2>&1 &
WEB_PID=$!

# ── Wait for the Web UI port to answer (anything under 500 counts) ──
echo "[dev] Waiting for the Web UI..."
web_ready=false
web_exited=false
for i in $(seq 1 "$WEB_WAIT_TIMEOUT"); do
    sleep 1
    if ! kill -0 "$WEB_PID" 2>/dev/null; then
        web_exited=true
        break
    fi
    http_code="$(curl -s -o /dev/null -w '%{http_code}' "$WEB_PROBE_URL" 2>/dev/null || true)"
    if [ -n "$http_code" ] && [ "$http_code" -ge 200 ] 2>/dev/null && [ "$http_code" -lt 500 ] 2>/dev/null; then
        web_ready=true
        break
    fi
    echo "  Attempt $i/${WEB_WAIT_TIMEOUT} - not ready yet..."
done

if [ "$web_exited" = "true" ]; then
    web_code=0
    wait "$WEB_PID" 2>/dev/null || web_code=$?
    red "[ERROR] The Web UI exited prematurely (exit code ${web_code})."
    print_log_tail "$WEB_LOG"
    exit 1
fi

if [ "$web_ready" != "true" ]; then
    red "[ERROR] The Web UI did not answer on ${WEB_PROBE_URL} within ${WEB_WAIT_TIMEOUT} seconds."
    gray "[dev]   Raise the limit with: PWNPROXY_WEBUI_TIMEOUT=120 ./dev.sh"
    print_log_tail "$WEB_LOG"
    exit 1
fi

echo "[dev] Web UI is ready!"

# ── Print URLs (only now, so the link works on the first click) ─
echo ""
echo "--- pwnproxy Dev Environment ---"
echo "  API     -> http://127.0.0.1:${API_PORT}"
echo "  Proxy   -> http://127.0.0.1:${PROXY_PORT}"
echo "  Docs    -> http://127.0.0.1:${API_PORT}/docs"
echo "  Web UI  -> ${WEB_UI_URL}"
if [ -n "$API_TOKEN" ]; then
    echo "             (open this URL: the token travels in the fragment, never to a server)"
else
    echo "             (open this URL and paste the token the UI asks for)"
fi
echo "  Log     -> ${LOG_FILE}"
echo "  Astro   -> ${WEB_LOG}"
echo "-------------------------------"
echo ""
echo "Press Ctrl+C to stop all services"
echo ""
echo "[dev] Web UI output follows (Ctrl+C stops everything)"

# ── Follow the Web UI output until Ctrl+C (or until it dies) ───
tail -n +1 -f "$WEB_LOG" &
TAIL_PID=$!

web_code=0
wait "$WEB_PID" 2>/dev/null || web_code=$?
if [ "$web_code" -ne 0 ]; then
    red "[ERROR] The Web UI stopped (exit code ${web_code})."
    print_log_tail "$WEB_LOG"
fi
