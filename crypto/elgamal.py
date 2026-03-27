from __future__ import annotations
from dataclasses import dataclass
from typing import Dict

from crypto.group import P, Q, G

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

