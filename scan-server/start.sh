#!/usr/bin/env bash
# Boot the local scan server + a cloudflared quick tunnel so internet
# requests reach this laptop. Ctrl-C tears both down.
set -euo pipefail
cd "$(dirname "$0")"

PORT="${PORT:-8787}"

echo "▶ starting scan server on :$PORT ..."
node server.js &
SERVER_PID=$!
trap 'echo; echo "▶ shutting down"; kill $SERVER_PID 2>/dev/null || true; kill ${TUNNEL_PID:-0} 2>/dev/null || true' EXIT INT TERM

# wait for health
for i in $(seq 1 20); do
  if curl -fsS "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1; then break; fi
  sleep 0.3
done

if ! command -v cloudflared >/dev/null 2>&1; then
  echo "✖ cloudflared not found. Install:  brew install cloudflared"
  echo "  Server is still running locally at http://127.0.0.1:$PORT"
  wait $SERVER_PID
fi

echo "▶ opening public tunnel (look for the https://*.trycloudflare.com URL below)"
echo "  → that URL + /api/scan is your public endpoint. Hand it to the website."
echo
cloudflared tunnel --url "http://127.0.0.1:$PORT" &
TUNNEL_PID=$!
wait $TUNNEL_PID
