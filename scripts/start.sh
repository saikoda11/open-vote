#!/usr/bin/env bash
set -e

[ ! -f config.json ] && python keygen.py
mkdir -p logs

for NODE in node1 node2 node3; do
  PORT=$(python -c "import json; c=json.load(open('config.json')); print(c['peers']['$NODE'].split(':')[-1])")
  echo "[start] Starting $NODE on port $PORT"
  VALIDATOR_ID=$NODE PRIVATE_KEY="keys/$NODE.key" CONFIG=config.json \
  DB_PATH="chain_$NODE.db" PORT=$PORT \
  python node.py > "logs/$NODE.log" 2>&1 &
  echo $! > "logs/$NODE.pid"
done

echo "Nodes started. Logs: logs/node{1,2,3}.log"
echo "Run the full election demo (no nodes needed):"
echo "  python demo.py"
echo ""
echo "Or drive the nodes manually:"
echo "  python authority_client.py setup --node http://127.0.0.1:8001"
echo "  python authority_client.py open  --node http://127.0.0.1:8001"
echo "  python voter_client.py --voter-id alice --candidate 0"
echo "  python voter_client.py --voter-id bob   --candidate 1"
echo "  python authority_client.py close   --node http://127.0.0.1:8001"
echo "  python authority_client.py decrypt --authority node1"
echo "  python authority_client.py decrypt --authority node2"
echo "  python authority_client.py tally   --node http://127.0.0.1:8001"