#!/bin/sh
set -e
# Clean up stray data dir from old defaults
rm -rf /app/data

if [ -d "/app/config" ]; then
  mkdir -p /app/config/data/logs
  # Seed config.yaml if volume doesn't have one
  if [ ! -f "/app/config/config.yaml" ]; then
    cp /app/config.default.yaml /app/config/config.yaml
  fi
  chown -R appuser:appuser /app/config/data
fi
exec su-exec appuser ./webridge "$@"
