#!/bin/sh
# pwnproxy backend entrypoint — starts proxy + API headless.
# Ports: 17170 (proxy), 17171 (API), 17173 (SSRF callback).
# They mirror DEFAULT_*_PORT in pwnproxy/shared/ports.py; override with the
# matching build/runtime config if you need different ones.
set -e

PROXY_PORT="${PROXY_PORT:-17170}"
API_PORT="${API_PORT:-17171}"
CALLBACK_PORT="${CALLBACK_PORT:-17173}"

echo "[entrypoint] Starting pwnproxy headless..."
python -c "from apps.terminal.cli import app; app()" start \
  --host 0.0.0.0 \
  --proxy-port "$PROXY_PORT" \
  --api-port "$API_PORT" \
  --callback-port "$CALLBACK_PORT" \
  --no-restore-session &
PWN_PID=$!

echo "[entrypoint] Waiting for API on :${API_PORT}..."
for i in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:${API_PORT}/api/v1/health" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$PWN_PID" 2>/dev/null; then
    echo "[entrypoint] pwnproxy exited prematurely." >&2
    exit 1
  fi
  sleep 1
done

echo "[entrypoint] Starting proxy subprocess (POST /proxy/start)..."
# The API requires Authorization: Bearer <token> on every route but /health.
# The token is created by the API on its first start and lives in the data
# volume ($HOME/.pwnproxy/api-token); PWNPROXY_API_TOKEN, when set, wins over it.
# Only the failure is logged: the token never goes to the container log.
TOKEN_FILE="${HOME:-/data}/.pwnproxy/api-token"
if [ -n "${PWNPROXY_API_TOKEN:-}" ]; then
  API_TOKEN="${PWNPROXY_API_TOKEN}"
elif [ -f "${TOKEN_FILE}" ]; then
  API_TOKEN="$(cat "${TOKEN_FILE}")"
else
  API_TOKEN=""
fi

if [ -z "${API_TOKEN}" ]; then
  echo "[entrypoint] WARNING: no API token at ${TOKEN_FILE} — proxy/start skipped." >&2
  echo "[entrypoint]   Read it with: docker compose exec backend cat ${TOKEN_FILE}" >&2
else
  curl -sf -X POST -H "Authorization: Bearer ${API_TOKEN}" \
    "http://127.0.0.1:${API_PORT}/api/v1/proxy/start" >/dev/null 2>&1 \
    || echo "[entrypoint] WARNING: proxy/start failed — proxy may not be listening."
fi

echo "[entrypoint] pwnproxy is up. Proxy :${PROXY_PORT}, API :${API_PORT}."
# Foreground: keep the container alive with the main process
wait "$PWN_PID"
