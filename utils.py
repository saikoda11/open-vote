import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def ed25519_priv_from_raw(raw: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(raw)

def ed25519_pub_from_raw(raw: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(raw)

def pubkey_raw(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
