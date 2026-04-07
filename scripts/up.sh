#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

if [ ! -f ".env" ]; then
  cp .env.example .env
  echo "Created .env from .env.example"
fi

docker compose --env-file .env up --build -d

echo ""
echo "gw-ipinfo-nginx is starting."
echo "Gateway: http://127.0.0.1:${GW_HTTP_PORT:-8080}"
echo "Health : http://127.0.0.1:${GW_HTTP_PORT:-8080}/healthz"
echo "Ready  : http://127.0.0.1:${GW_HTTP_PORT:-8080}/readyz"
echo "Metrics: http://127.0.0.1:${GW_HTTP_PORT:-8080}/metrics"
