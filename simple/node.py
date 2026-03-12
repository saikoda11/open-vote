import asyncio
import base64
import hashlib
import json
import logging
import os
import sqlite3
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

# ---------- logging ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("poa_node")


# ---------- utils ----------
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def ed25519_priv_from_raw(raw: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(raw)

def ed25519_pub_from_raw(raw: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(raw)

def pubkey_raw(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


# ---------- blockchain data ----------
@dataclass
class Block:
    index: int
    timestamp: float
    op: Dict[str, Any]
    prev_hash: str
    validator_id: str
    block_hash: str
    signature_b64: str


class SimplePoAChain:
    def __init__(self, authorities_pub_b64: Dict[str, str], db_path: str):
        self.authority_ids = sorted(authorities_pub_b64.keys())
        self.authorities_pub: Dict[str, Ed25519PublicKey] = {
            vid: ed25519_pub_from_raw(b64d(pub_b64))
            for vid, pub_b64 in authorities_pub_b64.items()
        }
        self.db_path = db_path
        self.chain: List[Block] = []
        self._init_db()
        self._load_from_db()

        if not self.chain:
            genesis = self._make_genesis()
            self.chain.append(genesis)
            self._persist_block(genesis)
            logger.info("Created genesis block: %s", genesis.block_hash)

    # ---------- persistence ----------
    def _init_db(self):
        con = sqlite3.connect(self.db_path)
        con.execute("""
            CREATE TABLE IF NOT EXISTS blocks (
                idx        INTEGER PRIMARY KEY,
                timestamp  REAL    NOT NULL,
                op         TEXT    NOT NULL,
                prev_hash  TEXT    NOT NULL,
                validator  TEXT    NOT NULL,
                block_hash TEXT    NOT NULL,
                signature  TEXT    NOT NULL
            )
        """)
        con.commit()
        con.close()

    def _persist_block(self, b: Block):
        con = sqlite3.connect(self.db_path)
        con.execute(
            "INSERT OR IGNORE INTO blocks VALUES (?,?,?,?,?,?,?)",
            (b.index, b.timestamp, json.dumps(b.op), b.prev_hash,
             b.validator_id, b.block_hash, b.signature_b64),
        )
        con.commit()
        con.close()

    def _load_from_db(self):
        con = sqlite3.connect(self.db_path)
        rows = con.execute("SELECT * FROM blocks ORDER BY idx").fetchall()
        con.close()
        for row in rows:
            idx, ts, op_json, prev_hash, validator, block_hash, sig = row
            self.chain.append(Block(
                index=idx,
                timestamp=ts,
                op=json.loads(op_json),
                prev_hash=prev_hash,
                validator_id=validator,
                block_hash=block_hash,
                signature_b64=sig,
            ))
        if self.chain:
            logger.info("Loaded %d blocks from DB (height=%d)", len(self.chain), self.chain[-1].index)

    # ---------- chain logic ----------
    def leader_for(self, height: int) -> str:
        return self.authority_ids[height % len(self.authority_ids)]

    def _header_bytes(self, index: int, timestamp: float, op: Dict[str, Any],
                      prev_hash: str, validator_id: str) -> bytes:
        obj = {
            "index": index,
            "timestamp": timestamp,
            "op": op,
            "prev_hash": prev_hash,
            "validator_id": validator_id,
        }
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _make_genesis(self) -> Block:
        index, ts, op = 0, 0.0, {"op": "genesis"}
        prev_hash = "0" * 64
        validator_id = self.leader_for(0)
        header = self._header_bytes(index, ts, op, prev_hash, validator_id)
        return Block(index, ts, op, prev_hash, validator_id, sha256_hex(header), b64e(b""))

    def head(self) -> Block:
        return self.chain[-1]

    def height(self) -> int:
        return self.head().index

    def state(self) -> List[Any]:
        return [b.op["value"] for b in self.chain[1:] if b.op.get("op") == "append"]

    def build_block(self, value: Any, signer: Ed25519PrivateKey, validator_id: str) -> Block:
        last = self.head()
        index = last.index + 1
        ts = time.time()
        op = {"op": "append", "value": value}

        expected = self.leader_for(index)
        if validator_id != expected:
            raise ValueError(f"Not leader for height {index}. Expected {expected}, got {validator_id}")
        if pubkey_raw(signer.public_key()) != pubkey_raw(self.authorities_pub[validator_id]):
            raise ValueError("Signer key does not match validator_id")

        header = self._header_bytes(index, ts, op, last.block_hash, validator_id)
        sig = signer.sign(header)
        return Block(index, ts, op, last.block_hash, validator_id, sha256_hex(header), b64e(sig))

    def verify_and_append(self, b: Block) -> None:
        last = self.head()

        if b.index != last.index + 1:
            raise ValueError(f"Out-of-order block. Expected {last.index + 1}, got {b.index}")
        if b.prev_hash != last.block_hash:
            raise ValueError("prev_hash mismatch")
        if b.validator_id != self.leader_for(b.index):
            raise ValueError(f"Wrong leader. Expected {self.leader_for(b.index)}, got {b.validator_id}")
        if b.op.get("op") != "append":
            raise ValueError(f"Invalid op: {b.op}")

        header = self._header_bytes(b.index, b.timestamp, b.op, b.prev_hash, b.validator_id)
        if b.block_hash != sha256_hex(header):
            raise ValueError("block_hash mismatch")

        pub = self.authorities_pub[b.validator_id]
        pub.verify(b64d(b.signature_b64), header)  # raises InvalidSignature on failure

        self.chain.append(b)
        self._persist_block(b)
        logger.info("Appended block #%d by %s hash=%s", b.index, b.validator_id, b.block_hash[:12])


# ---------- API models ----------
class AppendTx(BaseModel):
    value: Any

class BlockModel(BaseModel):
    index: int
    timestamp: float
    op: Dict[str, Any]
    prev_hash: str
    validator_id: str
    block_hash: str
    signature_b64: str


# ---------- config ----------
def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_private_key(path: str) -> Ed25519PrivateKey:
    raw = open(path, "rb").read()
    if len(raw) != 32:
        raise ValueError("Ed25519 raw private key must be 32 bytes.")
    return ed25519_priv_from_raw(raw)


CONFIG_PATH     = os.environ.get("CONFIG", "config.json")
VALIDATOR_ID    = os.environ.get("VALIDATOR_ID")
PRIVATE_KEY_PATH= os.environ.get("PRIVATE_KEY")
PORT            = int(os.environ.get("PORT", "8001"))
DB_PATH         = os.environ.get("DB_PATH", f"chain_{VALIDATOR_ID}.db")

if not VALIDATOR_ID:
    raise RuntimeError("Set env VALIDATOR_ID")
if not PRIVATE_KEY_PATH:
    raise RuntimeError("Set env PRIVATE_KEY=keys/<id>.key")

cfg             = load_config(CONFIG_PATH)
authorities_pub = cfg["authorities"]
peers: Dict[str, str] = cfg["peers"]

chain   = SimplePoAChain(authorities_pub, db_path=DB_PATH)
signer  = load_private_key(PRIVATE_KEY_PATH)

# Bounded mempool: max 1000 items; set for deduplication
from collections import deque
mempool: deque        = deque(maxlen=1000)
mempool_seen: set     = set()

# Lock protecting all chain mutations
chain_lock = asyncio.Lock()


# ---------- background tasks ----------
async def leader_loop():
    logger.info("Leader loop started for %s", VALIDATOR_ID)
    while True:
        await asyncio.sleep(0.4)

        next_height = chain.height() + 1
        if chain.leader_for(next_height) != VALIDATOR_ID:
            continue
        if not mempool:
            continue

        value = mempool.popleft()
        try:
            async with chain_lock:
                blk = chain.build_block(value=value, signer=signer, validator_id=VALIDATOR_ID)
                chain.verify_and_append(blk)
            await broadcast_block(blk)
        except Exception as e:
            logger.exception("Block production failed at height %d: %s", next_height, e)
            mempool.appendleft(value)   # put it back at the front


async def sync_loop():
    logger.info("Sync loop started for %s", VALIDATOR_ID)
    while True:
        await asyncio.sleep(5)
        try:
            await try_sync_from_peers()
        except Exception as e:
            logger.warning("Sync failed: %s", e)


async def broadcast_block(block: Block):
    payload = asdict(block)
    async with httpx.AsyncClient(timeout=3.0) as client:
        for vid, url in peers.items():
            if vid == VALIDATOR_ID:
                continue
            try:
                r = await client.post(f"{url}/block", json=payload)
                logger.debug("Broadcast #%d to %s → %s", block.index, vid, r.status_code)
            except Exception as e:
                logger.warning("Broadcast to %s failed: %s", vid, e)


async def try_sync_from_peers():
    my_h = chain.height()
    best_peer: Optional[str] = None
    best_h = my_h

    async with httpx.AsyncClient(timeout=3.0) as client:
        for vid, url in peers.items():
            if vid == VALIDATOR_ID:
                continue
            try:
                r = await client.get(f"{url}/chain/head")
                h = r.json()["height"]
                if h > best_h:
                    best_h, best_peer = h, url
            except Exception:
                pass

        if best_peer and best_h > my_h:
            logger.info("Syncing blocks %d..%d from %s", my_h + 1, best_h, best_peer)
            for idx in range(my_h + 1, best_h + 1):
                r = await client.get(f"{best_peer}/chain/block/{idx}")
                blk = Block(**r.json())
                async with chain_lock:
                    chain.verify_and_append(blk)


def _monitor_task(task: asyncio.Task, name: str):
    """Log if a background task crashes instead of silently dying."""
    def _on_done(t: asyncio.Task):
        if t.cancelled():
            logger.warning("Task %s was cancelled", name)
        elif t.exception():
            logger.error("Task %s crashed: %s", name, t.exception())
    task.add_done_callback(_on_done)


# ---------- lifespan ----------
@asynccontextmanager
async def lifespan(app: FastAPI):
    await try_sync_from_peers()

    t1 = asyncio.create_task(leader_loop())
    t2 = asyncio.create_task(sync_loop())
    _monitor_task(t1, "leader_loop")
    _monitor_task(t2, "sync_loop")

    yield

    t1.cancel()
    t2.cancel()


app = FastAPI(title=f"PoA Node ({VALIDATOR_ID})", lifespan=lifespan)


# ---------- endpoints ----------
@app.get("/chain/head")
def get_head():
    h = chain.head()
    return {"height": h.index, "block_hash": h.block_hash, "validator_id": h.validator_id}

@app.get("/state")
def get_state():
    return {"list": chain.state(), "height": chain.height()}

@app.get("/chain/block/{index}")
def get_block(index: int):
    if index < 0 or index >= len(chain.chain):
        raise HTTPException(404, "block not found")
    return asdict(chain.chain[index])

@app.post("/block")
async def receive_block(b: BlockModel):
    blk = Block(**b.model_dump())
    try:
        async with chain_lock:
            chain.verify_and_append(blk)
        return {"ok": True, "height": chain.height()}
    except Exception as e:
        raise HTTPException(400, f"rejected: {e}")

@app.post("/tx/append")
async def submit_append(tx: AppendTx):
    next_height = chain.height() + 1
    leader_id   = chain.leader_for(next_height)

    if leader_id != VALIDATOR_ID:
        leader_url = peers.get(leader_id)
        if not leader_url:
            raise HTTPException(500, f"No URL for leader {leader_id}")
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                r = await client.post(f"{leader_url}/tx/append", json=tx.model_dump())
            return {"forwarded_to": leader_id, "leader_response": r.json()}
        except Exception as e:
            raise HTTPException(502, f"Forward to {leader_id} failed: {e}")

    # Deduplicate by value hash
    tx_key = sha256_hex(json.dumps(tx.value, sort_keys=True).encode())
    if tx_key in mempool_seen:
        return {"accepted_by_leader": VALIDATOR_ID, "note": "duplicate, ignored"}

    mempool.append(tx.value)
    mempool_seen.add(tx_key)
    logger.info("Enqueued tx on %s, queue_len=%d", VALIDATOR_ID, len(mempool))
    return {"accepted_by_leader": VALIDATOR_ID, "queue_len": len(mempool)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="info")
