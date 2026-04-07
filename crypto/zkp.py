from __future__ import annotations
from dataclasses import dataclass

from crypto.group import (
    P, Q, G,
    group_exp, group_mul, group_inv,
    rand_scalar, hash_to_scalar,
)
from crypto.elgamal import Ciphertext


@dataclass
class BallotProof:
    a0: int
    b0: int
    a1: int
    b1: int
    c0: int
    c1: int
    r0: int
    r1: int

    def to_dict(self) -> dict:
        return {"a0": self.a0, "b0": self.b0, "a1": self.a1, "b1": self.b1,
                "c0": self.c0, "c1": self.c1, "r0": self.r0, "r1": self.r1}

    @staticmethod
    def from_dict(d: dict) -> "BallotProof":
        return BallotProof(**{k: int(v) for k, v in d.items()})


def _simulate_commitments(c: int, s: int, base1: int, X1: int, base2: int, X2: int):
    R1 = group_mul(group_exp(base1, s), group_exp(X1, c))
    R2 = group_mul(group_exp(base2, s), group_exp(X2, c))
    return R1, R2
