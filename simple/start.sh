#!/usr/bin/env bash
# Starts all 3 PoA nodes in the background, writing logs to logs/<id>.log
# Usage: ./start.sh
# Stop all: ./stop.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f config.json ]; then
  echo "[start] Generating keys and config..."
  python keygen.py
fi

mkdir -p logs

for NODE in node1 node2 node3; do
  PORT=$(python -c "import json; c=json.load(open('config.json')); print(c['peers']['$NODE'].split(':')[-1])")
  echo "[start] Starting $NODE on port $PORT"

  VALIDATOR_ID=$NODE \
  PRIVATE_KEY="keys/$NODE.key" \
  CONFIG=config.json \
  DB_PATH="chain_$NODE.db" \
  PORT=$PORT \
  python node.py > "logs/$NODE.log" 2>&1 &

  echo $! > "logs/$NODE.pid"
  echo "[start] $NODE pid=$(cat logs/$NODE.pid)"
done

echo ""
echo "All nodes started. Logs in ./logs/"
echo "  tail -f logs/node1.log"
echo ""
echo "Try:"
echo "  curl http://127.0.0.1:8001/state"
echo "  curl -X POST http://127.0.0.1:8001/tx/append -H 'Content-Type: application/json' -d '{\"value\": \"hello\"}'"