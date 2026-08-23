#!/bin/sh
# pwnproxy backend entrypoint — starts proxy + API headless.
# Ports: 8080 (proxy), 8000 (API), 18081 (SSRF callback).
set -e

echo "[entrypoint] Starting pwnproxy headless..."
python -c "from apps.terminal.cli import app; app()" start \
  --host 0.0.0.0 \
  --proxy-port 8080 \
  --api-port 8000 \
  --callback-port 18081 \
  --no-restore-session &
PWN_PID=$!

echo "[entrypoint] Waiting for API on :8000..."
for i in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:8000/api/v1/health" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$PWN_PID" 2>/dev/null; then
    echo "[entrypoint] pwnproxy exited prematurely." >&2
    exit 1
  fi
  sleep 1
done

echo "[entrypoint] Starting proxy subprocess (POST /proxy/start)..."
curl -sf -X POST "http://127.0.0.1:8000/api/v1/proxy/start" >/dev/null 2>&1 \
  || echo "[entrypoint] WARNING: proxy/start failed — proxy may not be listening."

echo "[entrypoint] pwnproxy is up. Proxy :8080, API :8000."
# Foreground: keep the container alive with the main process
wait "$PWN_PID"
