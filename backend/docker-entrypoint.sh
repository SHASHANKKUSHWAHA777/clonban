#!/bin/sh
# Waits for the bind-mounted ./backend source to actually be visible inside
# the container before starting uvicorn/the worker. On some Docker Desktop
# setups (Windows/Mac file sharing, fresh unzip, first `--build` run) the
# bind mount can take a moment to populate, which previously caused
# "ModuleNotFoundError: No module named 'app'" crash-loops. This turns that
# into a short, visible wait instead of an infinite restart spam.
set -e

MAX_WAIT=30
i=0
while [ ! -f /app/app/__init__.py ]; do
  i=$((i + 1))
  if [ "$i" -ge "$MAX_WAIT" ]; then
    echo "ERROR: /app/app/__init__.py still missing after ${MAX_WAIT}s."
    echo "This means the bind mount of ./backend into /app is not populated."
    echo "Check Docker Desktop > Settings > Resources > File Sharing includes this project's drive/folder,"
    echo "then run: docker compose down -v && docker compose up --build --force-recreate"
    exit 1
  fi
  echo "Waiting for /app source to mount... (${i}/${MAX_WAIT})"
  sleep 1
done

exec "$@"
