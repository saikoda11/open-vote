import argparse
import hashlib
import sys
import json
from typing import Any, Dict

import httpx
from crypto.merkle import verify_merkle_proof
from crypto.elgamal import encrypt
from crypto.zkp import prove_ballot
from election import Ballot

class Vote:
    def __init__(self, voter_data: Dict[str, Any]):
        self.voter_id: str = voter_data['voter_id']
        self.candidate = int(voter_data['candidate'])
        self.secret = int(voter_data["secret"])
        self.pk = int(voter_data["public_key"])
        self.leaf_index = int(voter_data["leaf_index"])
        self.merkle_proof = [tuple(x) for x in voter_data["merkle_proof"]]
        self.merkle_root = voter_data["merkle_root"]

    def _compute_nullifier(self, election_id: str) -> str:
        h = hashlib.sha256()
        h.update(self.secret.to_bytes(128, "big"))
        h.update(election_id.encode("utf-8"))
        return h.hexdigest()

    @staticmethod
    def from_json(json):
        roll = Vote(voter_data=json)
        return roll
    
    def validate(self, election_params: Dict[str, str]):
        # verify Merkle root matches what's on-chain
        if self.merkle_root != election_params["voter_roll_root"]:
            print("[error] Merkle root mismatch — voter roll may have changed")
            sys.exit(1)

        # verify own membership
        if not verify_merkle_proof(self.pk, self.leaf_index, self.merkle_proof, self.merkle_root):
            print("[error] Merkle proof invalid — voter not in roll")
            sys.exit(1)
    
    def to_ballot(self, election_params: Dict[str, Any]):
        # Build ballot with Nullifier, ZKP and encrypted message
        public_key = election_params["public_key"]
        election_id = election_params["election_id"]
        # Nullifier
        nullifier = self._compute_nullifier(election_id)
        print(f"[voter] Nullifier: {nullifier[:16]}...")

        # Encrypt ballot
        ct, randomness = encrypt(self.candidate, public_key)
        print(f"[voter] Ballot encrypted")

        # ZKP
        proof = prove_ballot(self.candidate, randomness, ct, public_key, election_id)
        print(f"[voter] ZKP generated")
        # voter_nullifier=d["voter_nullifier"],
        # ciphertext=Ciphertext.from_dict(d["ciphertext"]),
        # zkp=BallotProof.from_dict(d["zkp"]),
        # merkle_proof=[tuple(x) for x in d["merkle_proof"]],
        # leaf_index=int(d["leaf_index"]),
        return Ballot(
            voter_nullifier=nullifier,
            ciphertext=ct,
            zkp=proof,
            merkle_proof=self.merkle_proof,
            leaf_index=self.leaf_index,
        )

def cast_vote(voter_id: str, candidate: int, node_url: str) -> None:
    with open("voter_roll.json") as f:
        voter_roll = json.load(f)

    if voter_id not in voter_roll:
        print(f"[error] Voter '{voter_id}' not found in voter_roll.json")
        sys.exit(1)

    voter_data = voter_roll[voter_id]
    voter_data['voter_id'] = voter_id
    voter_data['candidate'] = candidate
    vote = Vote.from_json(voter_data)

    # Fetch election params from node
    r = httpx.get(f"{node_url}/election/params", timeout=5)
    if r.status_code != 200:
        print(f"[error] Could not fetch election params: {r.text}")
        sys.exit(1)
    params = r.json()
    
    vote.validate(election_params=params)
    ballot = vote.to_ballot(election_params=params)
    print(f"[voter] Casting vote for candidate {candidate} ({params['candidates'][candidate]})")
    print(f"[voter] Election: {params['election_id']}")

    # Submit
    payload = {"ballot": ballot.to_dict()}
    r = httpx.post(f"{node_url}/election/ballot", json=payload, timeout=10)
    if r.status_code == 200:
        print(f"o Ballot accepted {r.json()}")
    else:
        print(f"x Ballot rejected {r.status_code}: {r.text}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Cast a vote in the election")
    parser.add_argument("--voter-id",  required=True,  help="Your voter ID")
    parser.add_argument("--candidate", required=True,  type=int, choices=[0, 1],
                        help="0 = first candidate, 1 = second candidate")
    parser.add_argument("--node",      default="http://127.0.0.1:8001",
                        help="URL of any running node")
    args = parser.parse_args()
    cast_vote(args.voter_id, args.candidate, args.node)


if __name__ == "__main__":
    main()
