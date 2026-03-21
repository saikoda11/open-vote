import hashlib
import os

# TODO find proper prime field
P = -1
Q = -1
G = -1

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
