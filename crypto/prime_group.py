import hashlib
import os

# ---------------------------------------------------------------------------
# 1024-bit safe prime  (NIST / RFC 5114 — public, no trapdoor)
# p is prime, q = (p-1)//2 is prime, g generates the subgroup of order q.
# ---------------------------------------------------------------------------
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",
    16,
)
Q = (P - 1) // 2          # prime order of the subgroup
G = 2                      # generator of the subgroup of order Q in Z_P*

def mod_pow(num: int, exp: int, mod: int) -> int:
    return pow(num, exp, mod)

def group_inv(x: int) -> int:
    return pow(x, P - 2, P)

def group_mul(*args: int) -> int:
    result = 1
    for a in args:
        result = result * a % P
    return result

def group_exp(num: int, exp: int) -> int:
    return pow(num, exp % Q, P)

def rand_scalar() -> int:
    # random scalar in [1, Q-1]
    while True:
        r = int.from_bytes(os.urandom(128)) % Q
        if r != 0:
            return r

def hash_to_scalar(*parts) -> int:
    h = hashlib.sha256()
    for p in parts:
        part = None
        if isinstance(p, int):
            length = max(128, (p.bit_length() + 7) // 8)
            part = p.to_bytes(length)
        elif isinstance(p, str):
            part = p.encode("utf-8")
        elif isinstance(p, bytes):
            part = p
        else:
            part = str(p).encode("utf-8")
        h.update(part)
    return int.from_bytes(h.digest()) % Q
