import base64, json, os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

VALIDATORS = ["node1", "node2", "node3"]
PORTS      = {"node1": 8001, "node2": 8002, "node3": 8003}

os.makedirs("keys", exist_ok=True)
authorities = {}
for vid in VALIDATORS:
    priv    = Ed25519PrivateKey.generate()
    raw_priv = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    raw_pub  = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    with open(f"keys/{vid}.key", "wb") as f:
        f.write(raw_priv)
    authorities[vid] = base64.b64encode(raw_pub).decode()
    print(f"[keygen] wrote keys/{vid}.key")

peers  = {vid: f"http://127.0.0.1:{PORTS[vid]}" for vid in VALIDATORS}
config = {"authorities": authorities, "peers": peers}
with open("config.json", "w") as f:
    json.dump(config, f, indent=2)
print("[keygen] wrote config.json")
