import base64
import hashlib
import json
import os
import time
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
    op: Dict[str, Any]          # {"op":"append","value":...} (genesis uses {"op":"genesis"})
    prev_hash: str
    validator_id: str
    block_hash: str             # sha256(header_bytes)
    signature_b64: str          # Ed25519 signature over header_bytes


class SimplePoAChain:
    """
    Option A: round-robin leader produces the block and broadcasts it.
    Others verify + append. No votes, no BFT finality.
    """

    def __init__(self, authorities_pub_b64: Dict[str, str]):
        # Deterministic order across nodes:
        self.authority_ids = sorted(authorities_pub_b64.keys())

        self.authorities_pub: Dict[str, Ed25519PublicKey] = {
            vid: ed25519_pub_from_raw(b64d(pub_b64))
            for vid, pub_b64 in authorities_pub_b64.items()
        }

        self.chain: List[Block] = [self._make_genesis()]

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
        # Fully deterministic genesis across all nodes:
        index = 0
        ts = 0.0
        op = {"op": "genesis"}
        prev_hash = "0" * 64
        validator_id = self.leader_for(0)
        header = self._header_bytes(index, ts, op, prev_hash, validator_id)
        block_hash = sha256_hex(header)
        # No signature for genesis (or you can sign it if you want)
        return Block(index, ts, op, prev_hash, validator_id, block_hash, b64e(b""))

    def head(self) -> Block:
        return self.chain[-1]

    def height(self) -> int:
        return self.head().index

    def state(self) -> List[Any]:
        out: List[Any] = []
        for b in self.chain[1:]:
            if b.op.get("op") == "append":
                out.append(b.op.get("value"))
            else:
                raise ValueError(f"Unexpected op in chain at {b.index}: {b.op}")
        return out

    def build_block(self, value: Any, signer: Ed25519PrivateKey, validator_id: str) -> Block:
        last = self.head()
        index = last.index + 1
        ts = time.time()
        op = {"op": "append", "value": value}
        prev_hash = last.block_hash

        # Must be scheduled leader:
        expected = self.leader_for(index)
        if validator_id != expected:
            raise ValueError(f"Not leader for height {index}. Expected {expected}, got {validator_id}")

        # Must match validator_id public key:
        if pubkey_raw(signer.public_key()) != pubkey_raw(self.authorities_pub[validator_id]):
            raise ValueError("Signer private key does not match validator_id public key")

        header = self._header_bytes(index, ts, op, prev_hash, validator_id)
        sig = signer.sign(header)
        block_hash = sha256_hex(header)
        return Block(index, ts, op, prev_hash, validator_id, block_hash, b64e(sig))

    def verify_and_append(self, b: Block) -> None:
        last = self.head()

        # index + link checks:
        if b.index != last.index + 1:
            raise ValueError(f"Out of order block. Expected index {last.index + 1}, got {b.index}")
        if b.prev_hash != last.block_hash:
            raise ValueError("prev_hash mismatch")

        # leader schedule:
        expected_leader = self.leader_for(b.index)
        if b.validator_id != expected_leader:
            raise ValueError(f"Wrong leader. Expected {expected_leader}, got {b.validator_id}")

        # op validity:
        if b.op.get("op") != "append":
            raise ValueError(f"Invalid op: {b.op}")

        # hash correctness:
        header = self._header_bytes(b.index, b.timestamp, b.op, b.prev_hash, b.validator_id)
        if b.block_hash != sha256_hex(header):
            raise ValueError("block_hash mismatch")

        # signature correctness:
        pub = self.authorities_pub[b.validator_id]
        pub.verify(b64d(b.signature_b64), header)

        self.chain.append(b)


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


# ---------- node ----------
def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_private_key(path: str) -> Ed25519PrivateKey:
    raw = open(path, "rb").read()
    if len(raw) != 32:
        raise ValueError("Ed25519 raw private key must be 32 bytes (from keygen.py).")
    return ed25519_priv_from_raw(raw)

CONFIG_PATH = os.environ.get("CONFIG", "config.json")
VALIDATOR_ID = os.environ.get("VALIDATOR_ID")
PRIVATE_KEY_PATH = os.environ.get("PRIVATE_KEY")
PORT = int(os.environ.get("PORT", "8001"))

if not VALIDATOR_ID:
    raise RuntimeError("Set env VALIDATOR_ID")
if not PRIVATE_KEY_PATH:
    raise RuntimeError("Set env PRIVATE_KEY=keys/<id>.key")

cfg = load_config(CONFIG_PATH)
authorities_pub = cfg["authorities"]
peers: Dict[str, str] = cfg["peers"]

chain = SimplePoAChain(authorities_pub)
signer = load_private_key(PRIVATE_KEY_PATH)

# simple in-memory queue of pending values (leader only consumes)
mempool: List[Any] = []

app = FastAPI(title=f"PoA Node ({VALIDATOR_ID})")


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
def receive_block(b: BlockModel):
    blk = Block(**b.model_dump())
    try:
        chain.verify_and_append(blk)
        return {"ok": True, "height": chain.height()}
    except Exception as e:
        raise HTTPException(400, f"rejected block: {e}")

@app.post("/tx/append")
async def submit_append(tx: AppendTx):
    # leader for NEXT height:
    next_height = chain.height() + 1
    leader_id = chain.leader_for(next_height)

    if leader_id != VALIDATOR_ID:
        # forward to leader
        leader_url = peers.get(leader_id)
        if not leader_url:
            raise HTTPException(500, f"Leader URL not found for {leader_id}")
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                r = await client.post(f"{leader_url}/tx/append", json=tx.model_dump())
            return {"forwarded_to": leader_id, "leader_response": r.json()}
        except Exception as e:
            raise HTTPException(502, f"Failed to forward to leader {leader_id}: {e}")

    # I'm leader: enqueue
    mempool.append(tx.value)
    return {"accepted_by_leader": VALIDATOR_ID, "queue_len": len(mempool)}


async def broadcast_block(block: Block):
    payload = asdict(block)
    async with httpx.AsyncClient(timeout=3.0) as client:
        for vid, url in peers.items():
            if vid == VALIDATOR_ID:
                continue
            try:
                await client.post(f"{url}/block", json=payload)
            except Exception:
                # best-effort broadcast
                pass


async def try_sync_from_peers():
    # very simple sync: find max height, fetch missing blocks sequentially
    my_h = chain.height()
    best_peer = None
    best_h = my_h

    async with httpx.AsyncClient(timeout=3.0) as client:
        for vid, url in peers.items():
            if vid == VALIDATOR_ID:
                continue
            try:
                r = await client.get(f"{url}/chain/head")
                h = r.json()["height"]
                if h > best_h:
                    best_h = h
                    best_peer = url
            except Exception:
                pass

        if best_peer and best_h > my_h:
            for idx in range(my_h + 1, best_h + 1):
                r = await client.get(f"{best_peer}/chain/block/{idx}")
                blk = Block(**r.json())
                chain.verify_and_append(blk)


@app.on_event("startup")
async def startup_tasks():
    # try to sync on startup
    await try_sync_from_peers()


@app.on_event("startup")
async def leader_loop():
    # background loop: if I'm leader and have mempool, create blocks and broadcast
    while True:
        await asyncio_sleep(0.4)

        # try to sync occasionally if behind
        # (lightweight; avoids rejecting blocks due to missing height)
        if int(time.time()) % 5 == 0:
            try:
                await try_sync_from_peers()
            except Exception:
                pass

        next_height = chain.height() + 1
        leader_id = chain.leader_for(next_height)

        if leader_id != VALIDATOR_ID:
            continue
        if not mempool:
            continue

        value = mempool.pop(0)
        try:
            blk = chain.build_block(value=value, signer=signer, validator_id=VALIDATOR_ID)
            chain.verify_and_append(blk)  # append locally first
            await broadcast_block(blk)
        except Exception:
            # if something goes wrong, put tx back
            mempool.insert(0, value)


# tiny async sleep without importing asyncio at top-level too early (keeps it simple)
async def asyncio_sleep(seconds: float):
    import asyncio
    await asyncio.sleep(seconds)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=PORT)
