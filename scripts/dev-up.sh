#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

if [ ! -f ".env.debug" ]; then
  cp .env.debug.example .env.debug
  echo "Created .env.debug from .env.debug.example"
fi

docker compose -f docker-compose.debug.yml --env-file .env.debug up --build -d

echo ""
echo "gw-ipinfo-nginx debug stack is starting."
echo "Gateway: http://127.0.0.1:8080"
echo "Health : http://127.0.0.1:8080/healthz"
echo "Ready  : http://127.0.0.1:8080/readyz"
echo "Metrics: http://127.0.0.1:8080/metrics"
echo ""
echo "Quick test:"
echo "curl -i http://127.0.0.1:8080/ -H 'User-Agent: Mozilla/5.0'"
