#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

ENV_FILE=".env.debug"
if [ ! -f "$ENV_FILE" ]; then
  ENV_FILE=".env.debug.example"
fi

docker compose -f docker-compose.debug.yml --env-file "$ENV_FILE" logs -f gateway nginx
