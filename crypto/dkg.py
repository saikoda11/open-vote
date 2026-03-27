from dataclasses import dataclass
from typing import Dict, Tuple, List
from crypto.prime_group import P, Q, G, group_exp, group_mul, rand_scalar


@dataclass
class AuthorityKeys:
    authority_id:  str
    share_index:   int # 1-based
    sk_share:      int # share sk_j
    pk_share:      int # g^{sk_j}
    public_key:    int

def generate_polys(num_authorities, threshold):
    # each authority generates a random polynomial of degree t-1
    polys: List[List[int]] = []
    commitments: List[List[int]] = []   # Feldman commitments g^{a_ij}

    for _ in range(num_authorities):
        coeffs = [rand_scalar() for _ in range(threshold)]
        polys.append(coeffs)
        commitments.append([group_exp(G, c) for c in coeffs])
    return polys, commitments


def _eval_poly(coeffs: List[int], x: int) -> int:
    # Evaluate polynomial with given coefficients at x (Horner's method)
    result = 0
    for c in reversed(coeffs):
        result = (result * x + c) % Q
    return result

def _verify_key_shares(authority_ids, commitments, sk_shares):
    for auth_j in authority_ids:
        sk_j = sk_shares[auth_j]

        # Feldman verification (each authority can verify their own share):
        # g^{sk_j} should equal product_i product_l C_il^{x^l}
        expected = 1
        for i_commits in commitments:
            for l, C_il in enumerate(i_commits):
                expected = expected * group_exp(C_il, pow(x, l, Q)) % P
        actual = group_exp(G, sk_j)
        assert actual == expected, f"DKG verification failed for {auth_j}"
    return sk_shares


def compute_key_shares(authority_ids, polys):
    sk_shares: Dict[str, int] = {}
    for j_idx, auth_j in enumerate(authority_ids):
        x = j_idx + 1 # evaluation point
        sk_j = sum(_eval_poly(poly, x) for poly in polys) % Q
        sk_shares[auth_j] = sk_j
    return sk_shares


def generate_keys(
    authority_ids: List[str],
    threshold: int = 2,
) -> Tuple[int, Dict[str, AuthorityKeys]]:
    polys, commitments = generate_polys(len(authority_ids), threshold)
    sk_shares: Dict[str, int] = compute_key_shares(authority_ids, polys)
    _verify_key_shares(authority_ids, commitments, sk_shares)
 
    # Combined public key PK = g^{sum f_i(0)} = product of constant commitments
    public_key = 1
    for i_commits in commitments:
        public_key = public_key * i_commits[0] % P   # g^{a_i0} for each i

    # Build AuthorityKeys
    keys: Dict[str, AuthorityKeys] = {}
    for j_idx, auth_j in enumerate(authority_ids):
        sk_j = sk_shares[auth_j]
        keys[auth_j] = AuthorityKeys(
            authority_id=auth_j,
            share_index=j_idx + 1,
            sk_share=sk_j,
            pk_share=group_exp(G, sk_j),
            public_key=public_key,
        )
 
    return public_key, keys