import asyncio
import json
import logging
import os
from collections import deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

import httpx
from fastapi import FastAPI, HTTPException

from election import ElectionState, tx_ballot, tx_partial_decrypt, tx_tally
from election import Ballot

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("poa_node")

from utils import *
from blockchain import *
from models import *

# config
def load_config(path):
    with open(path) as f: return json.load(f)
def load_private_key(path):
    raw = open(path, "rb").read()
    if len(raw) != 32: raise ValueError("Expected 32-byte raw Ed25519 key")
    return ed25519_priv_from_raw(raw)

CONFIG_PATH      = os.environ.get("CONFIG", "config.json")
VALIDATOR_ID     = os.environ.get("VALIDATOR_ID")
PRIVATE_KEY_PATH = os.environ.get("PRIVATE_KEY")
PORT             = int(os.environ.get("PORT", "8001"))
DB_PATH          = os.environ.get("DB_PATH", f"chain_{VALIDATOR_ID}.db")

if not VALIDATOR_ID: 
    raise RuntimeError("Set env VALIDATOR_ID")
if not PRIVATE_KEY_PATH: 
    raise RuntimeError("Set env PRIVATE_KEY")

cfg             = load_config(CONFIG_PATH)
authorities_pub = cfg["authorities"]
peers: Dict[str, str] = cfg["peers"]

chain  = SimplePoAChain(authorities_pub, db_path=DB_PATH)
signer = load_private_key(PRIVATE_KEY_PATH)

mempool: deque    = deque(maxlen=1000)
mempool_seen: set = set()
chain_lock        = asyncio.Lock()


# helpers
def get_election_state() -> ElectionState:
    return ElectionState.from_chain(chain.state())

async def submit_tx(value: Any) -> dict:
    """Submit a transaction to this node's mempool (or forward to leader)."""
    next_height = chain.height() + 1
    leader_id   = chain.leader_for(next_height)

    if leader_id != VALIDATOR_ID:
        leader_url = peers.get(leader_id)
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(f"{leader_url}/tx/append", json={"value": value})
        return {"forwarded_to": leader_id, "response": r.json()}

    tx_key = sha256_hex(json.dumps(value, sort_keys=True).encode())
    if tx_key not in mempool_seen:
        mempool.append(value)
        mempool_seen.add(tx_key)
    return {"accepted": True, "queue_len": len(mempool)}


# background tasks of application lifespan
async def leader_loop():
    logger.info("Leader loop started for %s", VALIDATOR_ID)
    while True:
        await asyncio.sleep(0.4)
        next_height = chain.height() + 1
        if chain.leader_for(next_height) != VALIDATOR_ID or not mempool:
            continue
        value = mempool.popleft()
        try:
            async with chain_lock:
                blk = chain.build_block(value=value, signer=signer, validator_id=VALIDATOR_ID)
                chain.verify_and_append(blk)
            await broadcast_block(blk)
        except Exception as e:
            logger.exception("Block production failed: %s", e)
            mempool.appendleft(value)

async def sync_loop():
    while True:
        await asyncio.sleep(5)
        try:
            await try_sync_from_peers()
        except Exception as e:
            logger.warning("Sync failed: %s", e)

async def broadcast_block(block: Block):
    payload = asdict(block)
    async with httpx.AsyncClient(timeout=3.0) as client:
        for vid, url in peers.items():
            if vid == VALIDATOR_ID: continue
            try:
                await client.post(f"{url}/block", json=payload)
            except Exception as e:
                logger.warning("Broadcast to %s failed: %s", vid, e)

async def try_sync_from_peers():
    my_h = chain.height()
    best_peer, best_h = None, my_h
    async with httpx.AsyncClient(timeout=3.0) as client:
        for vid, url in peers.items():
            if vid == VALIDATOR_ID: continue
            try:
                r = await client.get(f"{url}/chain/head")
                h = r.json()["height"]
                if h > best_h: best_h, best_peer = h, url
            except Exception: pass
        if best_peer:
            for idx in range(my_h + 1, best_h + 1):
                r = await client.get(f"{best_peer}/chain/block/{idx}")
                blk = Block(**r.json())
                async with chain_lock:
                    chain.verify_and_append(blk)

def _monitor(task, name):
    def cb(t):
        if t.cancelled(): logger.warning("Task %s cancelled", name)
        elif t.exception(): logger.error("Task %s crashed: %s", name, t.exception())
    task.add_done_callback(cb)


# lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    await try_sync_from_peers()
    t1 = asyncio.create_task(leader_loop())
    t2 = asyncio.create_task(sync_loop())
    _monitor(t1, "leader_loop"); _monitor(t2, "sync_loop")
    yield
    t1.cancel(); t2.cancel()

app = FastAPI(title=f"PoA Voting Node ({VALIDATOR_ID})", lifespan=lifespan)


# chain endpoints
@app.get("/chain/head")
def get_head():
    h = chain.head()
    return {"height": h.index, "block_hash": h.block_hash, "validator_id": h.validator_id}

@app.get("/chain/block/{index}")
def get_block(index: int):
    if index < 0 or index >= len(chain.chain):
        raise HTTPException(404, "block not found")
    return asdict(chain.chain[index])

@app.post("/block")
async def receive_block(b: BlockModel):
    blk = Block(**b.model_dump())
    try:
        async with chain_lock:
            chain.verify_and_append(blk)
        return {"ok": True, "height": chain.height()}
    except Exception as e:
        raise HTTPException(400, f"rejected: {e}")

@app.post("/tx/append")
async def submit_append(tx: AppendTx):
    return await submit_tx(tx.value)


# election endpoints
@app.get("/election/params")
def election_params():
    state = get_election_state()
    if state.params is None:
        raise HTTPException(404, "No election set up yet")
    return state.params.to_dict()

@app.get("/election/state")
def election_state():
    state = get_election_state()
    return {
        "phase":         state.phase,
        "ballot_count":  len(state.ballots),
        "nullifiers":    list(state.nullifiers),
        "partial_decryptions": len(state.partial_decryptions),
        "tally":         state.tally,
        "candidates":    state.params.candidates if state.params else None,
    }

@app.post("/election/setup")
async def election_setup(tx: SetupTx):
    """Authority posts election parameters (after running DKG locally)."""
    state = get_election_state()
    if state.params is not None:
        raise HTTPException(400, "Election already set up")
    value = {"type": "SETUP", "params": tx.params}
    return await submit_tx(value)

@app.post("/election/open")
async def election_open():
    state = get_election_state()
    if state.params is None:
        raise HTTPException(400, "Election not set up")
    value = {"type": "OPEN_VOTING", "election_id": state.params.election_id}
    return await submit_tx(value)

@app.post("/election/close")
async def election_close():
    state = get_election_state()
    if state.phase.value != "VOTING":
        raise HTTPException(400, f"Not in VOTING phase (current: {state.phase})")
    value = {"type": "CLOSE_VOTING", "election_id": state.params.election_id}
    return await submit_tx(value)

@app.post("/election/ballot")
async def submit_ballot(tx: BallotTx):
    state = get_election_state()
    ballot = Ballot.from_dict(tx.ballot)
    ok, reason = state.validate_ballot(ballot)
    if not ok:
        raise HTTPException(400, f"Invalid ballot: {reason}")
    value = tx_ballot(state.params.election_id, ballot)
    logger.info("Accepted ballot with nullifier %s...", ballot.voter_nullifier[:12])
    return await submit_tx(value)

@app.post("/election/partial_decrypt")
async def submit_partial_decrypt(tx: PartialDecryptTx):
    from crypto.elgamal import PartialDecryption
    state = get_election_state()
    pd = PartialDecryption.from_dict(tx.partial_decryption)
    ok, reason = state.validate_partial_decryption(pd)
    if not ok:
        raise HTTPException(400, f"Invalid partial decryption: {reason}")
    value = tx_partial_decrypt(state.params.election_id, pd)
    logger.info("Accepted partial decryption from %s", pd.authority_id)
    return await submit_tx(value)

@app.post("/election/tally")
async def finalize_tally():
    state = get_election_state()
    if state.phase.value != "TALLYING":
        raise HTTPException(400, f"Not in TALLYING phase (current: {state.phase})")
    if len(state.partial_decryptions) < state.params.threshold:
        raise HTTPException(400,
            f"Need {state.params.threshold} partial decryptions, "
            f"have {len(state.partial_decryptions)}")
    result = state.compute_tally()
    value = tx_tally(state.params.election_id, result)
    logger.info("Tally computed: %s", result)
    return await submit_tx(value)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info")