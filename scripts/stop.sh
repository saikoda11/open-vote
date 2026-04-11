#!/usr/bin/env bash
for NODE in node1 node2 node3; do
  PID_FILE="logs/$NODE.pid"
  if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    kill "$PID" 2>/dev/null && echo "[stop] Stopped $NODE (pid=$PID)" || echo "[stop] $NODE not running"
    rm -f "$PID_FILE"
  fi
done
