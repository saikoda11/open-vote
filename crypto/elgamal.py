from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Tuple

from crypto.group import P, Q, G, rand_scalar, group_exp, group_mul

@dataclass
class Ciphertext:
    c1: int
    c2: int

    def to_dict(self) -> dict:
        return {"c1": self.c1, "c2": self.c2}

    @staticmethod
    def from_dict(d: dict) -> "Ciphertext":
        return Ciphertext(c1=int(d["c1"]), c2=int(d["c2"]))

    def __mul__(self, other: "Ciphertext") -> "Ciphertext":
        return Ciphertext(
            c1=self.c1 * other.c1 % P,
            c2=self.c2 * other.c2 % P,
        )

def encrypt(vote: int, public_key: int) -> Tuple[Ciphertext, int]:
    assert vote in (0, 1), "incorrect vote: vote must be 0 or 1"
    r = rand_scalar()
    c1 = group_exp(G, r)
    gv = group_exp(G, vote)     
    pkr = group_exp(public_key, r) 
    c2 = group_mul(gv, pkr)
    return Ciphertext(c1, c2), r
