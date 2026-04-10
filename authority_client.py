"""
minimal CLI for authorities to:
  1. Run DKG and publish election parameters  (setup)
  2. Open / close voting                      (open, close)
  3. Post a partial decryption                (decrypt)
  4. Trigger the final tally                  (tally)

Usage:
    python authority_client.py setup   --authority node1 --node http://127.0.0.1:8001
    python authority_client.py open    --node http://127.0.0.1:8001
    python authority_client.py close   --node http://127.0.0.1:8001
    python authority_client.py decrypt --authority node1 --node http://127.0.0.1:8001
    python authority_client.py tally   --node http://127.0.0.1:8001

Authority key shares are loaded from authority_keys.json (written by setup command).
"""

import argparse
import json
import sys

import httpx

from crypto.elgamal import partial_decrypt
from crypto.elgamal import combine_ciphertexts

def cmd_setup(authority_id: str, node_url: str) -> None:
    """Run DKG, write authority_keys.json + voter_roll.json, publish params."""
    from crypto.dkg import generate_keys
    from crypto.merkle import MerkleTree
    from crypto.prime_group import rand_scalar, group_exp, G
    import hashlib, os

    print("[setup] Running DKG for 3 authorities (threshold=2)...")
    authority_ids = ["node1", "node2", "node3"]
    public_key, keys = generate_keys(authority_ids, threshold=2)
    print(f"[setup] Combined public key: {hex(public_key)[:20]}...")

    # Save authority keys (in reality each authority keeps only their own)
    key_data = {
        vid: {
            "share_index":  k.share_index,
            "sk_share":     k.sk_share,
            "pk_share":     k.pk_share,
            "public_key":   k.public_key,
        }
        for vid, k in keys.items()
    }
    with open("authority_keys.json", "w") as f:
        json.dump(key_data, f, indent=2)
    print("[setup] Wrote authority_keys.json")

    # Build voter roll (hardcoded 5 voters for demo)
    print("[setup] Generating voter roll (5 voters)...")
    voter_ids = ["alice", "bob", "carol", "dave", "eve"]
    voter_secrets = {vid: rand_scalar() for vid in voter_ids}
    voter_pks     = {vid: group_exp(G, s) for vid, s in voter_secrets.items()}

    tree = MerkleTree(list(voter_pks.values()))
    print(f"[setup] Merkle root: {tree.root[:16]}...")

    voter_roll = {}
    for i, vid in enumerate(voter_ids):
        pk = voter_pks[vid]
        leaf_idx, proof = tree.proof(pk)
        voter_roll[vid] = {
            "secret":       voter_secrets[vid],
            "public_key":   pk,
            "leaf_index":   leaf_idx,
            "merkle_proof": proof,
            "merkle_root":  tree.root,
        }
    with open("voter_roll.json", "w") as f:
        json.dump(voter_roll, f, indent=2)
    print("[setup] Wrote voter_roll.json")

    # Election params
    election_id = hashlib.sha256(os.urandom(16)).hexdigest()[:16]
    params = {
        "election_id":       election_id,
        "candidates":        ["Alice", "Bob"],
        "public_key":        public_key,
        "pk_shares":         {vid: k.pk_share for vid, k in keys.items()},
        "share_indices":     {vid: k.share_index for vid, k in keys.items()},
        "voter_roll_root":   tree.root,
        "threshold":         2,
        "total_authorities": 3,
    }

    print(f"[setup] Publishing election {election_id} to chain...")
    r = httpx.post(f"{node_url}/election/setup", json={"params": params}, timeout=10)
    if r.status_code == 200:
        print(f"[setup] Election setup published -> {r.json()}")
    else:
        print(f"[setup] Failed: {r.status_code}: {r.text}")
        sys.exit(1)


def cmd_open(node_url: str) -> None:
    r = httpx.post(f"{node_url}/election/open", timeout=10)
    if r.status_code == 200:
        print(f"[open] Voting opened -> {r.json()}")
    else:
        print(f"[open] Failed: {r.status_code}: {r.text}")
        sys.exit(1)


def cmd_close(node_url: str) -> None:
    r = httpx.post(f"{node_url}/election/close", timeout=10)
    if r.status_code == 200:
        print(f"[close] Voting closed -> {r.json()}")
    else:
        print(f"[close] Failed: {r.status_code}: {r.text}")
        sys.exit(1)


def cmd_decrypt(authority_id: str, node_url: str) -> None:
    # Load authority keys
    with open("authority_keys.json") as f:
        key_data = json.load(f)
    if authority_id not in key_data:
        print(f"[decrypt] Unknown authority: {authority_id}")
        sys.exit(1)
    kd = key_data[authority_id]

    # Fetch election state
    r = httpx.get(f"{node_url}/election/state", timeout=5)
    state_data = r.json()
    if state_data["phase"] != "TALLYING":
        print(f"[decrypt] Election not in TALLYING phase: {state_data['phase']}")
        sys.exit(1)

    # Reconstruct combined ciphertext from chain
    r2 = httpx.get(f"{node_url}/election/params", timeout=5)
    params = r2.json()

    # Get all ballots by replaying chain state
    from election import ElectionState
    # Fetch raw chain state
    all_blocks = []
    height = httpx.get(f"{node_url}/chain/head", timeout=5).json()["height"]
    chain_values = []
    for i in range(1, height + 1):
        blk = httpx.get(f"{node_url}/chain/block/{i}", timeout=5).json()
        val = blk["op"].get("value")
        if val: chain_values.append(val)

    estate = ElectionState.from_chain(chain_values)
    if not estate.ballots:
        print("[decrypt] No ballots found")
        sys.exit(1)

    combined = combine_ciphertexts(estate.ballots_ciphertext_list())
    print(f"[decrypt] Combined {len(estate.ballots)} ballots homomorphically")

    # Partial decrypt
    ski      = int(kd["sk_share"])
    pk_share = int(kd["pk_share"])
    pd = partial_decrypt(
        authority_id=authority_id,
        share_index=int(kd["share_index"]),
        ski=ski,
        pk_share=pk_share,
        ct=combined,
    )
    print(f"[decrypt] Partial decryption computed, posting to chain...")

    r3 = httpx.post(
        f"{node_url}/election/partial_decrypt",
        json={"partial_decryption": pd.to_dict()},
        timeout=10,
    )
    if r3.status_code == 200:
        print(f"[decrypt] Partial decryption accepted -> {r3.json()}")
    else:
        print(f"[decrypt] Failed: {r3.status_code}: {r3.text}")
        sys.exit(1)


def cmd_tally(node_url: str) -> None:
    r = httpx.post(f"{node_url}/election/tally", timeout=10)
    if r.status_code == 200:
        print(f"[tally] Tally finalized ✓")
        # Print result
        r2 = httpx.get(f"{node_url}/election/state", timeout=5)
        state = r2.json()
        print(f"\n{'='*40}")
        print(f"  ELECTION RESULT")
        print(f"{'='*40}")
        for candidate, count in state["tally"].items():
            print(f"  {candidate:10s}: {count} votes")
        print(f"{'='*40}\n")
    else:
        print(f"[tally] Failed: {r.status_code}: {r.text}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Authority client for ZKP election")
    sub = parser.add_subparsers(dest="command", required=True)

    p_setup = sub.add_parser("setup",   help="Run DKG and publish election params")
    p_setup.add_argument("--authority", default="node1")
    p_setup.add_argument("--node",      default="http://127.0.0.1:8001")

    p_open  = sub.add_parser("open",    help="Open voting phase")
    p_open.add_argument("--node",       default="http://127.0.0.1:8001")

    p_close = sub.add_parser("close",   help="Close voting phase")
    p_close.add_argument("--node",      default="http://127.0.0.1:8001")

    p_dec   = sub.add_parser("decrypt", help="Post partial decryption")
    p_dec.add_argument("--authority",   required=True)
    p_dec.add_argument("--node",        default="http://127.0.0.1:8001")

    p_tally = sub.add_parser("tally",   help="Finalize tally")
    p_tally.add_argument("--node",      default="http://127.0.0.1:8001")

    args = parser.parse_args()

    if args.command == "setup":
        cmd_setup(args.authority, args.node)
    elif args.command == "open":
        cmd_open(args.node)
    elif args.command == "close":
        cmd_close(args.node)
    elif args.command == "decrypt":
        cmd_decrypt(args.authority, args.node)
    elif args.command == "tally":
        cmd_tally(args.node)


if __name__ == "__main__":
    main()