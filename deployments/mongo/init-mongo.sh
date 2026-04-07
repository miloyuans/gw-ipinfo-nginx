#!/bin/sh
set -eu

# This script runs only during first-time container initialization when the
# data directory is empty. Use the temporary local init server directly and
# create the application user idempotently.
mongosh --host 127.0.0.1 --quiet <<EOF
use ${MONGO_APP_DATABASE}

if (!db.getUser("${MONGO_APP_USERNAME}")) {
  db.createUser({
    user: "${MONGO_APP_USERNAME}",
    pwd: "${MONGO_APP_PASSWORD}",
    roles: [
      { role: "readWrite", db: "${MONGO_APP_DATABASE}" }
    ]
  })
}
EOF
