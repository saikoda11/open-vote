import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def hmac_sign(secret: bytes, msg: str) -> str:
    # returns hex signature
    return hmac.new(secret, msg.encode("utf-8"), hashlib.sha256).hexdigest()


@dataclass
class Block:
    index: int
    timestamp: float
    op: Dict[str, Any]        # only {"op":"append","value":...}
    prev_hash: str
    validator_id: str         # which authority produced this block
    block_hash: str           # sha256(header) (header excludes signature)
    signature: str            # HMAC(secret_of_validator, block_hash)


class PoABlockchain:
    """
    PoA = only approved validators may create blocks.
    Validity = chain links + operation validity + validator is authorized + signature verifies.
    Optional: enforce round-robin leader schedule (simple).
    """

    def __init__(self, authorities: Dict[str, bytes], enforce_round_robin: bool = True):
        """
        authorities: dict {validator_id -> secret_key_bytes}
        enforce_round_robin: if True, block i must be signed by authorities[i % n]
        """
        if not authorities:
            raise ValueError("Need at least 1 authority.")
        self.authorities = authorities
        self.authority_ids = list(authorities.keys())
        self.enforce_round_robin = enforce_round_robin

        self.chain: List[Block] = [self._make_genesis_block()]

    def _expected_validator(self, index: int) -> str:
        return self.authority_ids[index % len(self.authority_ids)]

    def _header(self, index: int, timestamp: float, op: Dict[str, Any], prev_hash: str, validator_id: str) -> str:
        # Canonical JSON -> stable hash
        header_obj = {
            "index": index,
            "timestamp": timestamp,
            "op": op,
            "prev_hash": prev_hash,
            "validator_id": validator_id,
        }
        return json.dumps(header_obj, sort_keys=True, separators=(",", ":"))

    def _make_genesis_block(self) -> Block:
        ts = time.time()
        op = {"op": "append", "value": "__GENESIS__"}  # ignored in state()
        validator_id = self._expected_validator(0)
        header = self._header(0, ts, op, "0" * 64, validator_id)
        block_hash = sha256(header)
        signature = hmac_sign(self.authorities[validator_id], block_hash)
        return Block(
            index=0,
            timestamp=ts,
            op=op,
            prev_hash="0" * 64,
            validator_id=validator_id,
            block_hash=block_hash,
            signature=signature,
        )

    def append(self, value: Any, validator_id: Optional[str] = None) -> Block:
        last = self.chain[-1]
        idx = last.index + 1
        ts = time.time()
        op = {"op": "append", "value": value}

        if validator_id is None:
            validator_id = self._expected_validator(idx)

        if validator_id not in self.authorities:
            raise ValueError(f"Validator {validator_id!r} is not an authorized authority.")

        if self.enforce_round_robin:
            expected = self._expected_validator(idx)
            if validator_id != expected:
                raise ValueError(f"Wrong validator for block {idx}. Expected {expected!r}, got {validator_id!r}.")

        header = self._header(idx, ts, op, last.block_hash, validator_id)
        block_hash = sha256(header)
        signature = hmac_sign(self.authorities[validator_id], block_hash)

        b = Block(
            index=idx,
            timestamp=ts,
            op=op,
            prev_hash=last.block_hash,
            validator_id=validator_id,
            block_hash=block_hash,
            signature=signature,
        )
        self.chain.append(b)
        return b

    def state(self) -> List[Any]:
        out: List[Any] = []
        for b in self.chain[1:]:  # ignore genesis
            if b.op.get("op") != "append":
                raise ValueError(f"Invalid operation in block {b.index}: {b.op}")
            out.append(b.op.get("value"))
        return out

    def print_list(self) -> None:
        print(self.state())

    def verify(self) -> bool:
        for i in range(len(self.chain)):
            b = self.chain[i]

            # 1) validator must be authorized
            if b.validator_id not in self.authorities:
                return False

            # 2) optional schedule (round-robin)
            if self.enforce_round_robin:
                if b.validator_id != self._expected_validator(b.index):
                    return False

            # 3) prev-hash link
            if b.index == 0:
                if b.prev_hash != "0" * 64:
                    return False
            else:
                if b.prev_hash != self.chain[i - 1].block_hash:
                    return False

            # 4) operation validity
            if b.index != 0 and b.op.get("op") != "append":
                return False

            # 5) hash correctness
            header = self._header(b.index, b.timestamp, b.op, b.prev_hash, b.validator_id)
            expected_hash = sha256(header)
            if b.block_hash != expected_hash:
                return False

            # 6) signature correctness
            secret = self.authorities[b.validator_id]
            expected_sig = hmac_sign(secret, b.block_hash)
            if not hmac.compare_digest(b.signature, expected_sig):
                return False

        return True


if __name__ == "__main__":
    # Authorities (toy secrets). In real PoA use public/private keypairs.
    authorities = {
        "commission": b"super-secret-key-1",
        "observer_partyA": b"super-secret-key-2",
        "observer_partyB": b"super-secret-key-3",
    }

    bc = PoABlockchain(authorities, enforce_round_robin=True)

    bc.append("Alice")         # auto-picked validator by round-robin
    bc.append("Bob")
    bc.append(123)

    bc.print_list()            # ['Alice', 'Bob', 123]
    print("valid?", bc.verify())

    # Tamper demo (should fail)
    bc.chain[2].op["value"] = "MALLORY"
    print("valid after tamper?", bc.verify())
