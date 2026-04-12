"""
election.py
Election state machine layered on top of the PoA chain.
All state transitions are recorded as chain transactions.
The election state can be fully reconstructed from the chain alone.
"""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from crypto.elgamal import (
    Ciphertext, combine_ciphertexts,
    PartialDecryption, verify_partial_decryption, combine_partial_decryptions,
)
from crypto.zkp import BallotProof, verify_ballot_proof


class Phase(str, Enum):
    SETUP     = "SETUP" #authorities run DKG, publish election parameters
    VOTING    = "VOTING" # voters cast ballots (verified on receipt)
    TALLYING  = "TALLYING" # authorities post partial decryptions
    FINISHED  = "FINISHED" # tally is published


@dataclass
class ElectionParams:
    election_id:    str
    candidates:     List[str]          # ["Alice", "Bob"]
    public_key:     int                # combined ElGamal PK
    pk_shares:      Dict[str, int]     # authority_id → g^ski
    share_indices:  Dict[str, int]     # authority_id → 1-based index
    voter_roll_root: str               # Merkle root
    threshold:      int
    total_authorities: int

    def to_dict(self) -> dict:
        return {
            "election_id":       self.election_id,
            "candidates":        self.candidates,
            "public_key":        self.public_key,
            "pk_shares":         {k: v for k, v in self.pk_shares.items()},
            "share_indices":     self.share_indices,
            "voter_roll_root":   self.voter_roll_root,
            "threshold":         self.threshold,
            "total_authorities": self.total_authorities,
        }

    @staticmethod
    def from_dict(d: dict) -> "ElectionParams":
        return ElectionParams(
            election_id=d["election_id"],
            candidates=d["candidates"],
            public_key=int(d["public_key"]),
            pk_shares={k: int(v) for k, v in d["pk_shares"].items()},
            share_indices=d["share_indices"],
            voter_roll_root=d["voter_roll_root"],
            threshold=int(d["threshold"]),
            total_authorities=int(d["total_authorities"]),
        )


@dataclass
class Ballot:
    voter_nullifier: str               # H(voter_secret || election_id)
    ciphertext:      Ciphertext
    zkp:             BallotProof
    merkle_proof:    List[Tuple[str, str]]   # [(sibling_hash, side), ...]
    leaf_index:      int

    def to_dict(self) -> dict:
        return {
            "voter_nullifier": self.voter_nullifier,
            "ciphertext":      self.ciphertext.to_dict(),
            "zkp":             self.zkp.to_dict(),
            "merkle_proof":    self.merkle_proof,
            "leaf_index":      self.leaf_index,
        }

    @staticmethod
    def from_dict(d: dict) -> "Ballot":
        return Ballot(
            voter_nullifier=d["voter_nullifier"],
            ciphertext=Ciphertext.from_dict(d["ciphertext"]),
            zkp=BallotProof.from_dict(d["zkp"]),
            merkle_proof=[tuple(x) for x in d["merkle_proof"]],
            leaf_index=int(d["leaf_index"]),
        )

    def is_valid(self, election_pk, election_id):
        return verify_ballot_proof(
            self.zkp,
            self.ciphertext,
            election_pk,
            election_id,
        )


# Transaction types
def tx_setup(params: ElectionParams) -> dict:
    return {"type": "SETUP", "params": params.to_dict()}

def tx_open_voting(election_id: str) -> dict:
    return {"type": "OPEN_VOTING", "election_id": election_id}

def tx_ballot(election_id: str, ballot: Ballot) -> dict:
    return {"type": "BALLOT", "election_id": election_id, "ballot": ballot.to_dict()}

def tx_partial_decrypt(election_id: str, pd: PartialDecryption) -> dict:
    return {"type": "PARTIAL_DECRYPT", "election_id": election_id, "pd": pd.to_dict()}

def tx_close_voting(election_id: str) -> dict:
    return {"type": "CLOSE_VOTING", "election_id": election_id}

def tx_tally(election_id: str, result: Dict[str, int]) -> dict:
    return {"type": "TALLY", "election_id": election_id, "result": result}


# ElectionState — reconstructed by replaying chain transactions
class ElectionState:
    """
    Reconstructs the current election state from a list of chain values
    (the `list` returned by /state endpoint).
    """

    def __init__(self):
        self.phase:              Phase                        = Phase.SETUP
        self.params:             Optional[ElectionParams]    = None
        self.ballots:            List[Ballot]                = []
        self.nullifiers:         set                         = set()
        self.partial_decryptions: List[PartialDecryption]   = []
        self.tally:              Optional[Dict[str, int]]    = None

    def apply(self, value: Any) -> None:
        """Apply a single transaction value to update state."""
        if not isinstance(value, dict):
            return
        t = value.get("type")

        if t == "SETUP":
            self.params = ElectionParams.from_dict(value["params"])
            self.phase  = Phase.SETUP
        elif t == "OPEN_VOTING":
            if self.phase == Phase.SETUP:
                self.phase = Phase.VOTING
        elif t == "BALLOT":
            ballot = Ballot.from_dict(value["ballot"])
            self.ballots.append(ballot)
            self.nullifiers.add(ballot.voter_nullifier)
        elif t == "CLOSE_VOTING":
            if self.phase == Phase.VOTING:
                self.phase = Phase.TALLYING
        elif t == "PARTIAL_DECRYPT":
            pd = PartialDecryption.from_dict(value["pd"])
            self.partial_decryptions.append(pd)
        elif t == "TALLY":
            self.tally = value["result"]
            self.phase = Phase.FINISHED

    @classmethod
    def from_chain(cls, chain_list: List[Any]) -> "ElectionState":
        state = cls()
        for value in chain_list:
            state.apply(value)
        return state

    # Validation helpers (called by nodes before accepting transactions)
    def validate_ballot(self, ballot: Ballot) -> Tuple[bool, str]:
        """Full ballot validation. Returns (ok, reason)."""
        if self.phase != Phase.VOTING:
            return False, f"Election not in VOTING phase (current: {self.phase})"
        if self.params is None:
            return False, "No election params"

        # check if voter nullifier is in nullifiers
        if ballot.voter_nullifier in self.nullifiers:
            return False, "Nullifier already used (double vote attempt)"

        # check validity of ballot choice
        if not ballot.is_valid(self.params.public_key, self.params.election_id):
            return False, "Invalid ballot ZKP"

        return True, "ok"

    def validate_partial_decryption(self, pd: PartialDecryption) -> Tuple[bool, str]:
        if self.phase != Phase.TALLYING:
            return False, f"Not in TALLYING phase (current: {self.phase})"
        if self.params is None:
            return False, "No election params"
        if pd.authority_id not in self.params.pk_shares:
            return False, f"Unknown authority: {pd.authority_id}"

        # Check for duplicate:
        existing_ids = {p.authority_id for p in self.partial_decryptions}
        if pd.authority_id in existing_ids:
            return False, f"Authority {pd.authority_id} already submitted partial decryption"

        # Verify Chaum-Pedersen proof:
        combined = combine_ciphertexts(self.ballots_ciphertext_list())
        pk_share = self.params.pk_shares[pd.authority_id]
        if not verify_partial_decryption(pd, pk_share, combined):
            return False, "Invalid Chaum-Pedersen proof on partial decryption"

        return True, "ok"

    def ballots_ciphertext_list(self) -> List[Ciphertext]:
        return [b.ciphertext for b in self.ballots]

    def compute_tally(self) -> Dict[str, int]:
        # Combine partial decryptions and return dict containing {candidate: count}
        assert self.params is not None
        if len(self.partial_decryptions) < self.params.threshold:
            raise ValueError(
                f"Need {self.params.threshold} partial decryptions, "
                f"have {len(self.partial_decryptions)}"
            )

        combined = combine_ciphertexts(self.ballots_ciphertext_list())
        total_votes_for_1 = combine_partial_decryptions(
            self.partial_decryptions,
            combined,
            threshold=self.params.threshold,
            total=self.params.total_authorities,
        )
        total = len(self.ballots)
        votes_for_0 = total - total_votes_for_1
        return {
            self.params.candidates[0]: votes_for_0,
            self.params.candidates[1]: total_votes_for_1,
        }