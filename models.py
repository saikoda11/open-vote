from pydantic import BaseModel
from typing import Any, Dict

class AppendTx(BaseModel):
    value: Any

class BlockModel(BaseModel):
    index: int; timestamp: float; op: Dict[str, Any]
    prev_hash: str; validator_id: str; block_hash: str; signature_b64: str

class BallotTx(BaseModel):
    ballot: dict       # serialized Ballot

class PartialDecryptTx(BaseModel):
    partial_decryption: dict

class SetupTx(BaseModel):
    params: dict

class TallyTx(BaseModel):
    result: Dict[str, int]