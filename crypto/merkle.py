import hashlib
from typing import List

def _hash_node(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _hash_pair(left: str, right: str) -> str:
    return _hash_node(bytes.fromhex(left) + bytes.fromhex(right))

class MerkleTree:
    def __init__(self, voter_pks: List[int]):
        """
        voter_pks - public keys of voters
        """
        self.leaves: List[str] = [
            _hash_node(pk.to_bytes((pk.bit_length() + 7) // 8 or 1, "big"))
            for pk in voter_pks
        ]
        self.tree: List[List[str]] = self.build()
    
    def build(self):
        """
        Build the tree bottom-up. tree[0] = leaves, tree[-1] = [root].
        first n are hashes of all leaves
        next n/2 are hashes of (i, i+1) pairs and so on.
        """
        level = list(self.leaves)
        tree = [level]
        while len(level) > 1:
            if len(level) % 2 == 1:
                level = level + [level[-1]] # duplicate last leaf to pad
            next_level = [
                _hash_pair(level[i], level[i + 1])
                for i in range(0, len(level), 2)
            ]
            tree.append(next_level)
            level = next_level
        return tree

    def proof(self, voter_pk: int):
        """
        Generate a Merkle proof for voter_pk.

        Returns:
            leaf_index: position of this voter in the tree
            path: list of (sibling_hash, side) where side ∈ {'left', 'right'}
        """
        leaf_hash = _hash_node(voter_pk.to_bytes((voter_pk.bit_length() + 7) // 8 or 1, "big"))
        try:
            idx = self.leaves.index(leaf_hash)
        except ValueError:
            raise ValueError("Voter public key not in voter roll")

        path: List[Tuple[str, str]] = []
        current_idx = idx
        for level in self.tree[:-1]:
            padded = level if len(level) % 2 == 0 else level + [level[-1]]
            sibling_idx = current_idx + (+1 if current_idx % 2 == 0 else -1)
            side = "right" if current_idx % 2 == 0 else "left"
            if sibling_idx < len(padded):
                path.append((padded[sibling_idx], side))
            else:
                path.append((padded[current_idx], side))
            current_idx //= 2

        return idx, path
