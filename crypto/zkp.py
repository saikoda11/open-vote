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


def prove_ballot(
    vote: int,
    randomness: int,
    ct: Ciphertext,
    public_key: int,
    election_id: str,
) -> BallotProof:
    assert vote in (0, 1)

    G_inv   = group_inv(G)
    C2_mod1 = ct.c2 * G_inv % P 

    if vote == 0:
        c1_sim = rand_scalar()
        s1_sim = rand_scalar()
        a1, b1 = _simulate_commitments(c1_sim, s1_sim, G, ct.c1, public_key, C2_mod1)

        k0 = rand_scalar()
        a0 = group_exp(G, k0)
        b0 = group_exp(public_key, k0)

        challenge = hash_to_scalar(
            G, public_key, ct.c1, ct.c2, a0, b0, a1, b1, election_id
        )
        c0 = (challenge - c1_sim) % Q
        s0 = (k0 - c0 * randomness) % Q

        return BallotProof(a0=a0, b0=b0, a1=a1, b1=b1, c0=c0, c1=c1_sim, r0=s0, r1=s1_sim)

    else:
        c0_sim = rand_scalar()
        s0_sim = rand_scalar()
        a0, b0 = _simulate_commitments(c0_sim, s0_sim, G, ct.c1, public_key, ct.c2)

        k1 = rand_scalar()
        a1 = group_exp(G, k1)
        b1 = group_exp(public_key, k1)

        challenge = hash_to_scalar(
            G, public_key, ct.c1, ct.c2, a0, b0, a1, b1, election_id
        )
        c1 = (challenge - c0_sim) % Q
        s1 = (k1 - c1 * randomness) % Q

        return BallotProof(a0=a0, b0=b0, a1=a1, b1=b1, c0=c0_sim, c1=c1, r0=s0_sim, r1=s1)


def verify_ballot_proof(
    proof: BallotProof,
    ct: Ciphertext,
    public_key: int,
    election_id: str,
) -> bool:
    G_inv   = group_inv(G)
    C2_mod1 = ct.c2 * G_inv % P

    challenge = hash_to_scalar(
        G, public_key, ct.c1, ct.c2,
        proof.a0, proof.b0, proof.a1, proof.b1,
        election_id,
    )
    if (proof.c0 + proof.c1) % Q != challenge:
        return False

    if group_mul(group_exp(G, proof.r0), group_exp(ct.c1, proof.c0)) != proof.a0:
        return False
    if group_mul(group_exp(public_key, proof.r0), group_exp(ct.c2, proof.c0)) != proof.b0:
        return False

    if group_mul(group_exp(G, proof.r1), group_exp(ct.c1, proof.c1)) != proof.a1:
        return False
    if group_mul(group_exp(public_key, proof.r1), group_exp(C2_mod1, proof.c1)) != proof.b1:
        return False

    return True
