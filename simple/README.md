# 3-Node PoA Blockchain

A minimal Proof-of-Authority blockchain with 3 validator nodes running locally.

## Setup

```bash
pip install -r requirements.txt
```

## Running

```bash
# Generate keys + config, then start all 3 nodes:
chmod +x start.sh stop.sh
./start.sh

# Stop all nodes:
./stop.sh
```

## Manual key generation (optional)

```bash
python keygen.py
# Writes keys/node1.key, keys/node2.key, keys/node3.key
# Writes config.json with public keys + peer URLs
```

## Testing

```bash
# Run after ./start.sh
python test_cluster.py
```

## Interacting manually

```bash
# Check state on any node:
curl http://127.0.0.1:8001/state
curl http://127.0.0.1:8002/state
curl http://127.0.0.1:8003/state

# Submit a transaction to any node (it auto-forwards to the current leader):
curl -X POST http://127.0.0.1:8001/tx/append \
  -H 'Content-Type: application/json' \
  -d '{"value": "hello world"}'

# Check chain head:
curl http://127.0.0.1:8001/chain/head

# Fetch a specific block:
curl http://127.0.0.1:8001/chain/block/1
```

## How it works

- **Round-robin leaders**: `node1` produces blocks at heights 1,4,7..., `node2` at 2,5,8..., `node3` at 3,6,9...
- **Transaction forwarding**: Submit to any node — if it isn't the next leader it forwards the tx automatically
- **Block broadcast**: The leader broadcasts each new block to all peers immediately
- **Sync on startup**: Each node fetches missing blocks from peers before starting its loop
- **Periodic sync**: Each node re-syncs every 5 seconds to catch up if it missed a broadcast
- **Persistence**: Each node writes its chain to `chain_<id>.db` (SQLite), survives restarts

## File structure

```
├── node.py          # Node implementation
├── keygen.py        # Key generation
├── test_cluster.py  # Smoke tests
├── requirements.txt
├── start.sh         # Start all 3 nodes
├── stop.sh          # Stop all 3 nodes
├── config.json      # Generated: public keys + peer URLs (auto-created)
├── keys/            # Generated: private key files (auto-created)
└── logs/            # Node stdout/stderr logs (auto-created)
```