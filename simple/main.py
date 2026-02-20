import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def pubkey_raw(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def pubkey_from_raw(raw: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(raw)


@dataclass
class Block:
    index: int
    timestamp: float
    op: Dict[str, Any]       # only {"op":"append","value":...}
    prev_hash: str
    validator_id: str
    block_hash: str          # sha256(header_bytes) hex
    signature_b64: str       # Ed25519 signature over header_bytes (base64)


class PoABlockchainEd25519:
    """
    PoA membership: only approved validator public keys may sign blocks.
    This is still a *single-node* toy chain (no networking/consensus),
    but it enforces: authorized signer + valid signature + hash-links.

    Optionally enforces a round-robin "leader schedule".
    """

    def __init__(self, authorities_pubkeys: Dict[str, bytes], enforce_round_robin: bool = True):
        """
        authorities_pubkeys: {validator_id -> public_key_raw_32bytes}
        """
        if not authorities_pubkeys:
            raise ValueError("Need at least one authority public key.")
        self.authorities_pubkeys = authorities_pubkeys
        self.authority_ids = list(authorities_pubkeys.keys())
        self.enforce_round_robin = enforce_round_robin
        self.chain: List[Block] = [self._make_genesis_block()]

    def _expected_validator(self, index: int) -> str:
        return self.authority_ids[index % len(self.authority_ids)]

    def _header_bytes(
        self,
        index: int,
        timestamp: float,
        op: Dict[str, Any],
        prev_hash: str,
        validator_id: str,
    ) -> bytes:
        # Canonical JSON => stable hash + signature
        header_obj = {
            "index": index,
            "timestamp": timestamp,
            "op": op,
            "prev_hash": prev_hash,
            "validator_id": validator_id,
        }
        return json.dumps(header_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _pub_for_validator(self, validator_id: str) -> Ed25519PublicKey:
        raw = self.authorities_pubkeys.get(validator_id)
        if raw is None:
            raise ValueError(f"Unknown validator_id {validator_id!r}")
        return pubkey_from_raw(raw)

    def _assert_authorized_and_schedule(self, validator_id: str, index: int) -> None:
        if validator_id not in self.authorities_pubkeys:
            raise ValueError(f"Validator {validator_id!r} is not authorized.")
        if self.enforce_round_robin:
            expected = self._expected_validator(index)
            if validator_id != expected:
                raise ValueError(f"Wrong validator for block {index}. Expected {expected!r}, got {validator_id!r}.")

    def _make_genesis_block(self) -> Block:
        ts = time.time()
        op = {"op": "append", "value": "__GENESIS__"}  # ignored in state()

        validator_id = self._expected_validator(0)
        self._assert_authorized_and_schedule(validator_id, 0)

        header = self._header_bytes(0, ts, op, "0" * 64, validator_id)
        block_hash = sha256_hex(header)

        # For demo we cannot sign genesis unless we have some validator privkey.
        # So we make genesis "unsigned" by choosing a convention: signature over header is empty.
        # If you want genesis signed too, create chain with a known signer private key.
        signature_b64 = b64e(b"")  # empty signature

        return Block(
            index=0,
            timestamp=ts,
            op=op,
            prev_hash="0" * 64,
            validator_id=validator_id,
            block_hash=block_hash,
            signature_b64=signature_b64,
        )

    def append(self, value: Any, signer_private_key: Ed25519PrivateKey, validator_id: Optional[str] = None) -> Block:
        last = self.chain[-1]
        idx = last.index + 1
        ts = time.time()
        op = {"op": "append", "value": value}

        if validator_id is None:
            validator_id = self._expected_validator(idx)

        self._assert_authorized_and_schedule(validator_id, idx)

        # Ensure the provided private key corresponds to validator_id (prevents "sign as someone else")
        signer_pub_raw = pubkey_raw(signer_private_key.public_key())
        expected_pub_raw = self.authorities_pubkeys[validator_id]
        if signer_pub_raw != expected_pub_raw:
            raise ValueError("Signer private key does not match the validator_id public key.")

        header = self._header_bytes(idx, ts, op, last.block_hash, validator_id)
        block_hash = sha256_hex(header)
        signature = signer_private_key.sign(header)

        b = Block(
            index=idx,
            timestamp=ts,
            op=op,
            prev_hash=last.block_hash,
            validator_id=validator_id,
            block_hash=block_hash,
            signature_b64=b64e(signature),
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
        for i, b in enumerate(self.chain):
            # 1) authorized validator + schedule
            if b.validator_id not in self.authorities_pubkeys:
                return False
            if self.enforce_round_robin and b.validator_id != self._expected_validator(b.index):
                return False

            # 2) prev hash link
            if b.index == 0:
                if b.prev_hash != "0" * 64:
                    return False
            else:
                if b.prev_hash != self.chain[i - 1].block_hash:
                    return False

            # 3) op validity (skip genesis)
            if b.index != 0 and b.op.get("op") != "append":
                return False

            # 4) hash correctness
            header = self._header_bytes(b.index, b.timestamp, b.op, b.prev_hash, b.validator_id)
            expected_hash = sha256_hex(header)
            if b.block_hash != expected_hash:
                return False

            # 5) signature correctness (skip genesis here because we used empty signature convention)
            if b.index != 0:
                pub = self._pub_for_validator(b.validator_id)
                try:
                    pub.verify(b64d(b.signature_b64), header)
                except Exception:
                    return False

        return True


# --- Demo helpers ---
def make_validator(validator_id: str) -> Tuple[str, Ed25519PrivateKey, bytes]:
    priv = Ed25519PrivateKey.generate()
    pub_raw = pubkey_raw(priv.public_key())
    return validator_id, priv, pub_raw


if __name__ == "__main__":
    # Create 3 validators (private keys stay local; public keys are shared)
    v1_id, v1_priv, v1_pub = make_validator("commission")
    v2_id, v2_priv, v2_pub = make_validator("observer_partyA")
    v3_id, v3_priv, v3_pub = make_validator("observer_partyB")

    authorities = {v1_id: v1_pub, v2_id: v2_pub, v3_id: v3_pub}

    bc = PoABlockchainEd25519(authorities_pubkeys=authorities, enforce_round_robin=True)

    # Round-robin expects: block1->observer_partyA, block2->observer_partyB, block3->commission, ...
    bc.append("Alice", signer_private_key=v2_priv, validator_id="observer_partyA")
    bc.append("Bob", signer_private_key=v3_priv, validator_id="observer_partyB")
    bc.append(123, signer_private_key=v1_priv, validator_id="commission")

    bc.print_list()                 # ['Alice', 'Bob', 123]
    print("valid?", bc.verify())    # True

    # Tamper demo (should fail verification)
    bc.chain[2].op["value"] = "MALLORY"
    print("valid after tamper?", bc.verify())  # False
