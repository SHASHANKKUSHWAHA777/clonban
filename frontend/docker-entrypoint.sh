#!/bin/sh
# Same rationale as backend/docker-entrypoint.sh: waits for the bind-mounted
# ./frontend source to be visible before running npm, instead of failing
# immediately with "ENOENT ... package.json" and restart-looping.
set -e

MAX_WAIT=30
i=0
while [ ! -f /app/package.json ]; do
  i=$((i + 1))
  if [ "$i" -ge "$MAX_WAIT" ]; then
    echo "ERROR: /app/package.json still missing after ${MAX_WAIT}s."
    echo "This means the bind mount of ./frontend into /app is not populated."
    echo "Check Docker Desktop > Settings > Resources > File Sharing includes this project's drive/folder,"
    echo "then run: docker compose down -v && docker compose up --build --force-recreate"
    exit 1
  fi
  echo "Waiting for /app source to mount... (${i}/${MAX_WAIT})"
  sleep 1
done

# node_modules is an anonymous volume seeded at build time; if it's ever
# empty (e.g. volume recreated) reinstall so `next dev` doesn't fail.
if [ ! -d /app/node_modules/.bin ]; then
  echo "node_modules missing/empty, running npm install..."
  npm install
fi

exec "$@"
