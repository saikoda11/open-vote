#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

for NODE in node1 node2 node3; do
  PID_FILE="logs/$NODE.pid"
  if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
      echo "[stop] Stopping $NODE (pid=$PID)"
      kill "$PID"
    else
      echo "[stop] $NODE not running"
    fi
    rm -f "$PID_FILE"
  fi
done