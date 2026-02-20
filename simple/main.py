import hashlib
import json
import time
from dataclasses import dataclass, asdict
from typing import Any, List, Dict


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


@dataclass
class Block:
    index: int
    timestamp: float
    op: Dict[str, Any]          # only {"op":"append","value":...}
    prev_hash: str
    nonce: int
    hash: str


class AppendOnlyBlockchain:
    def __init__(self, difficulty: int = 2):
        """
        difficulty=0 disables proof-of-work.
        difficulty=2 means hash must start with '00'.
        """
        self.difficulty = difficulty
        self.chain: List[Block] = [self._make_genesis_block()]

    def _block_payload(self, index: int, timestamp: float, op: Dict[str, Any], prev_hash: str, nonce: int) -> str:
        # Canonical JSON so hashing is stable
        payload = {
            "index": index,
            "timestamp": timestamp,
            "op": op,
            "prev_hash": prev_hash,
            "nonce": nonce,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def _mine_hash(self, index: int, timestamp: float, op: Dict[str, Any], prev_hash: str) -> (int, str):
        prefix = "0" * self.difficulty
        nonce = 0
        while True:
            payload = self._block_payload(index, timestamp, op, prev_hash, nonce)
            h = sha256(payload)
            if self.difficulty == 0 or h.startswith(prefix):
                return nonce, h
            nonce += 1

    def _make_genesis_block(self) -> Block:
        ts = time.time()
        op = {"op": "append", "value": "__GENESIS__"}  # doesn’t have to affect state (we’ll ignore it)
        nonce, h = self._mine_hash(index=0, timestamp=ts, op=op, prev_hash="0" * 64)
        return Block(index=0, timestamp=ts, op=op, prev_hash="0" * 64, nonce=nonce, hash=h)

    def append(self, value: Any) -> Block:
        op = {"op": "append", "value": value}
        last = self.chain[-1]
        idx = last.index + 1
        ts = time.time()
        nonce, h = self._mine_hash(index=idx, timestamp=ts, op=op, prev_hash=last.hash)
        b = Block(index=idx, timestamp=ts, op=op, prev_hash=last.hash, nonce=nonce, hash=h)
        self.chain.append(b)
        return b

    def state(self) -> List[Any]:
        result: List[Any] = []
        for b in self.chain[1:]:  # ignore genesis
            if b.op.get("op") != "append":
                raise ValueError(f"Invalid operation in block {b.index}: {b.op}")
            result.append(b.op.get("value"))
        return result

    def print_list(self) -> None:
        print(self.state())

    def verify(self) -> bool:
        prefix = "0" * self.difficulty
        for i in range(1, len(self.chain)):
            cur = self.chain[i]
            prev = self.chain[i - 1]

            if cur.prev_hash != prev.hash:
                return False

            payload = self._block_payload(cur.index, cur.timestamp, cur.op, cur.prev_hash, cur.nonce)
            expected_hash = sha256(payload)

            if cur.hash != expected_hash:
                return False

            if self.difficulty != 0 and not cur.hash.startswith(prefix):
                return False

            if cur.op.get("op") != "append":
                return False

        return True


if __name__ == "__main__":
    bc = AppendOnlyBlockchain(difficulty=2)  # set 0 to disable PoW
    bc.append("Alice")
    bc.append("Bob")
    bc.append(123)

    bc.print_list()          # -> ['Alice', 'Bob', 123]
    print("valid?", bc.verify())
