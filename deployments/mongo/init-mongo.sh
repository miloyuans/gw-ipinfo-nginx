#!/bin/sh
set -eu

mongosh --host 127.0.0.1 \
  -u "${MONGO_INITDB_ROOT_USERNAME}" \
  -p "${MONGO_INITDB_ROOT_PASSWORD}" \
  --authenticationDatabase admin <<EOF
use ${MONGO_APP_DATABASE}

db.createUser({
  user: "${MONGO_APP_USERNAME}",
  pwd: "${MONGO_APP_PASSWORD}",
  roles: [
    { role: "readWrite", db: "${MONGO_APP_DATABASE}" }
  ]
})
EOF
