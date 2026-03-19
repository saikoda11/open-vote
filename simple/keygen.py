import base64
import json
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

VALIDATORS = ["node1", "node2", "node3"]
PORTS = {"node1": 8001, "node2": 8002, "node3": 8003}

os.makedirs("keys", exist_ok=True)

authorities = {}
for vid in VALIDATORS:
    priv = Ed25519PrivateKey.generate()
    raw_priv = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    raw_pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_path = f"keys/{vid}.key"
    with open(key_path, "wb") as f:
        f.write(raw_priv)
    authorities[vid] = base64.b64encode(raw_pub).decode("ascii")
    print(f"[keygen] wrote {key_path} (32 bytes)")

peers = {vid: f"http://127.0.0.1:{PORTS[vid]}" for vid in VALIDATORS}

config = {"authorities": authorities, "peers": peers}
with open("config.json", "w") as f:
    json.dump(config, f, indent=2)

print("\n[keygen] wrote config.json")
print(json.dumps(config, indent=2))
