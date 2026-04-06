#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

if [ ! -f ".env.prod" ]; then
  cp .env.prod.example .env.prod
  echo "Created .env.prod from .env.prod.example"
  echo "Edit .env.prod before enabling real IPinfo and Mongo access."
fi

docker compose -f docker-compose.prod.yml --env-file .env.prod up --build -d

echo ""
echo "gw-ipinfo-nginx production-like stack is starting."
echo "Gateway: http://127.0.0.1:8080"
echo "Health : http://127.0.0.1:8080/healthz"
echo "Ready  : http://127.0.0.1:8080/readyz"
echo ""
echo "Follow logs with:"
echo "sh ./scripts/prod-logs.sh"
