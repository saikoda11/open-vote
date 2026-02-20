import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from collections import Counter

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
    op: Dict[str, Any]       # {"op":"vote","voter_id":...,"choice":...}
    prev_hash: str
    validator_id: str
    block_hash: str          # sha256(header_bytes)
    signature_b64: str       # Ed25519(signature over header_bytes)


class PoAVotingBlockchain:
    """
    Simplest voting ledger:
      - Append-only blocks
      - Each block contains one vote: (voter_id, choice)
      - NO double-vote prevention (duplicates allowed)
      - PoA: only authorized validators can sign blocks
    """

    def __init__(self, authorities_pubkeys: Dict[str, bytes], enforce_round_robin: bool = True):
        if not authorities_pubkeys:
            raise ValueError("Need at least one authority public key.")
        self.authorities_pubkeys = authorities_pubkeys  # {validator_id -> pubkey_raw}
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
        op = {"op": "genesis"}
        validator_id = self._expected_validator(0)

        header = self._header_bytes(0, ts, op, "0" * 64, validator_id)
        block_hash = sha256_hex(header)

        # Genesis is unsigned by convention in this toy example
        return Block(
            index=0,
            timestamp=ts,
            op=op,
            prev_hash="0" * 64,
            validator_id=validator_id,
            block_hash=block_hash,
            signature_b64=b64e(b""),
        )

    def cast_vote(
        self,
        voter_id: str,
        choice: str,
        signer_private_key: Ed25519PrivateKey,
        validator_id: Optional[str] = None,
    ) -> Block:
        last = self.chain[-1]
        idx = last.index + 1
        ts = time.time()

        op = {
            "op": "vote",
            "voter_id": voter_id,
            "choice": choice,
        }

        if validator_id is None:
            validator_id = self._expected_validator(idx)

        self._assert_authorized_and_schedule(validator_id, idx)

        # Ensure the signer key matches the validator_id public key
        signer_pub_raw = pubkey_raw(signer_private_key.public_key())
        if signer_pub_raw != self.authorities_pubkeys[validator_id]:
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

    # --- Reading results ---

    def votes(self) -> List[Tuple[str, str]]:
        """Returns the raw list of votes as [(voter_id, choice), ...] (duplicates allowed)."""
        out: List[Tuple[str, str]] = []
        for b in self.chain[1:]:
            if b.op.get("op") == "vote":
                out.append((b.op["voter_id"], b.op["choice"]))
        return out

    def tally(self) -> Counter:
        """Counts all votes. If someone voted twice, both are counted (as requested)."""
        return Counter(choice for _, choice in self.votes())

    def verify(self) -> bool:
        for i, b in enumerate(self.chain):
            # validator exists + optional schedule
            if b.validator_id not in self.authorities_pubkeys:
                return False
            if self.enforce_round_robin and b.validator_id != self._expected_validator(b.index):
                return False

            # prev link
            if b.index == 0:
                if b.prev_hash != "0" * 64:
                    return False
            else:
                if b.prev_hash != self.chain[i - 1].block_hash:
                    return False

            # op validity
            if b.index != 0:
                if b.op.get("op") != "vote":
                    return False
                if "voter_id" not in b.op or "choice" not in b.op:
                    return False

            # hash correctness
            header = self._header_bytes(b.index, b.timestamp, b.op, b.prev_hash, b.validator_id)
            if b.block_hash != sha256_hex(header):
                return False

            # signature correctness (skip genesis)
            if b.index != 0:
                pub = self._pub_for_validator(b.validator_id)
                try:
                    pub.verify(b64d(b.signature_b64), header)
                except Exception:
                    return False

        return True


# --- Demo / setup ---
def make_validator(validator_id: str) -> Tuple[str, Ed25519PrivateKey, bytes]:
    priv = Ed25519PrivateKey.generate()
    return validator_id, priv, pubkey_raw(priv.public_key())


if __name__ == "__main__":
    # 2 authorities for demo
    vA_id, vA_priv, vA_pub = make_validator("commission")
    vB_id, vB_priv, vB_pub = make_validator("observer")

    authorities = {vA_id: vA_pub, vB_id: vB_pub}
    bc = PoAVotingBlockchain(authorities_pubkeys=authorities, enforce_round_robin=True)

    # Round-robin: block1 -> observer, block2 -> commission, block3 -> observer, ...
    bc.cast_vote("Alice", "Candidate_X", signer_private_key=vB_priv, validator_id="observer")
    bc.cast_vote("Bob", "Candidate_Y", signer_private_key=vA_priv, validator_id="commission")
    bc.cast_vote("Alice", "Candidate_X", signer_private_key=vB_priv, validator_id="observer")  # double vote allowed

    print("Votes:", bc.votes())
    print("Tally:", bc.tally())
    print("Chain valid?", bc.verify())
