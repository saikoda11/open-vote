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
        TODO
        """
        pass