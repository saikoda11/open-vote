from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Tuple

from crypto.group import P, Q, G, group_exp, group_mul, group_inv, rand_scalar, hash_to_scalar

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


@dataclass
class PartialDecryption: # Chaum-Pedersen proof
    authority_id: str
    share_index:  int    
    di:           int     
    
    cp_commitment_g:   int  
    cp_commitment_c1:  int  
    cp_challenge:      int
    cp_response:       int  

    def to_dict(self) -> dict:
        return {
            "authority_id":     self.authority_id,
            "share_index":      self.share_index,
            "di":               self.di,
            "cp_commitment_g":  self.cp_commitment_g,
            "cp_commitment_c1": self.cp_commitment_c1,
            "cp_challenge":     self.cp_challenge,
            "cp_response":      self.cp_response,
        }

    @staticmethod
    def from_dict(d: dict) -> "PartialDecryption":
        return PartialDecryption(**{k: (int(v) if k != "authority_id" else v) for k, v in d.items()})


def partial_decrypt(
    authority_id: str,
    share_index: int,
    ski: int,        
    pk_share: int,    
    ct: Ciphertext,
) -> PartialDecryption:
    
    di = group_exp(ct.c1, ski)

    t = rand_scalar()
    Rt_g  = group_exp(G, t) 
    Rt_c1 = group_exp(ct.c1, t)  
    challenge = hash_to_scalar(G, ct.c1, pk_share, di, Rt_g, Rt_c1, authority_id)
    response = (t - challenge * ski) % Q

    return PartialDecryption(
        authority_id=authority_id,
        share_index=share_index,
        di=di,
        cp_commitment_g=Rt_g,
        cp_commitment_c1=Rt_c1,
        cp_challenge=challenge,
        cp_response=response,
    )


def verify_partial_decryption(pd: PartialDecryption, pk_share: int, ct: Ciphertext) -> bool:
    expected_challenge = hash_to_scalar(
        G, ct.c1, pk_share, pd.di,
        pd.cp_commitment_g, pd.cp_commitment_c1,
        pd.authority_id,
    )
    if pd.cp_challenge != expected_challenge:
        return False

    # Check:  g^response * pk_share^challenge == commitment_g
    lhs_g = group_mul(
        group_exp(G,        pd.cp_response),
        group_exp(pk_share, pd.cp_challenge),
    )
    if lhs_g != pd.cp_commitment_g:
        return False

    # Check:  C1^response * di^challenge == commitment_c1
    lhs_c1 = group_mul(
        group_exp(ct.c1, pd.cp_response),
        group_exp(pd.di, pd.cp_challenge),
    )
    if lhs_c1 != pd.cp_commitment_c1:
        return False

    return True


