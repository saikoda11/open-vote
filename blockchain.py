import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from utils import *
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("poa_node")

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

    def _init_db(self):
        con = sqlite3.connect(self.db_path)
        con.execute("""CREATE TABLE IF NOT EXISTS blocks (
            idx INTEGER PRIMARY KEY, timestamp REAL, op TEXT,
            prev_hash TEXT, validator TEXT, block_hash TEXT, signature TEXT)""")
        con.commit(); con.close()

    def _persist_block(self, b: Block):
        con = sqlite3.connect(self.db_path)
        con.execute("INSERT OR IGNORE INTO blocks VALUES (?,?,?,?,?,?,?)",
            (b.index, b.timestamp, json.dumps(b.op), b.prev_hash,
             b.validator_id, b.block_hash, b.signature_b64))
        con.commit(); con.close()

    def _load_from_db(self):
        con = sqlite3.connect(self.db_path)
        rows = con.execute("SELECT * FROM blocks ORDER BY idx").fetchall()
        con.close()
        for row in rows:
            idx, ts, op_json, prev_hash, validator, block_hash, sig = row
            self.chain.append(Block(idx, ts, json.loads(op_json), prev_hash, validator, block_hash, sig))
        if self.chain:
            logger.info("Loaded %d blocks from DB (height=%d)", len(self.chain), self.chain[-1].index)

    def leader_for(self, height: int) -> str:
        return self.authority_ids[height % len(self.authority_ids)]

    def _header_bytes(self, index, timestamp, op, prev_hash, validator_id) -> bytes:
        return json.dumps({"index": index, "timestamp": timestamp, "op": op,
            "prev_hash": prev_hash, "validator_id": validator_id},
            sort_keys=True, separators=(",", ":")).encode()

    def _make_genesis(self) -> Block:
        index, ts, op = 0, 0.0, {"op": "genesis"}
        prev_hash = "0" * 64
        vid = self.leader_for(0)
        header = self._header_bytes(index, ts, op, prev_hash, vid)
        return Block(index, ts, op, prev_hash, vid, sha256_hex(header), b64e(b""))

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
        if validator_id != self.leader_for(index):
            raise ValueError(f"Not leader for height {index}")
        if pubkey_raw(signer.public_key()) != pubkey_raw(self.authorities_pub[validator_id]):
            raise ValueError("Key mismatch")
        header = self._header_bytes(index, ts, op, last.block_hash, validator_id)
        sig = signer.sign(header)
        return Block(index, ts, op, last.block_hash, validator_id, sha256_hex(header), b64e(sig))

    def verify_and_append(self, b: Block) -> None:
        last = self.head()
        if b.index != last.index + 1:
            raise ValueError(f"Out-of-order: expected {last.index+1}, got {b.index}")
        if b.prev_hash != last.block_hash:
            raise ValueError("prev_hash mismatch")
        if b.validator_id != self.leader_for(b.index):
            raise ValueError(f"Wrong leader")
        if b.op.get("op") != "append":
            raise ValueError(f"Invalid op")
        header = self._header_bytes(b.index, b.timestamp, b.op, b.prev_hash, b.validator_id)
        if b.block_hash != sha256_hex(header):
            raise ValueError("block_hash mismatch")
        self.authorities_pub[b.validator_id].verify(b64d(b.signature_b64), header)
        self.chain.append(b)
        self._persist_block(b)
        logger.info("Block #%d by %s", b.index, b.validator_id)