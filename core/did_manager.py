"""
W3C DID 管理 + 链上存证记录
"""
import hashlib
import time
from datetime import datetime, timezone
from core.fingerprint import canonical_json

DID_PREFIX = "did:trust:livestock"

def generate_did(entity_type: str = "data", seed: str = None) -> dict:
    if seed is None:
        seed = __import__('os').urandom(32).hex()
    sid = hashlib.sha256(f"{entity_type}:{seed}:{time.time()}".encode()).hexdigest()[:32]
    return {
        "did": f"{DID_PREFIX}:{entity_type}:{sid}",
        "entity_type": entity_type,
        "specific_id": sid,
        "created": datetime.now(timezone.utc).isoformat(),
    }

def create_on_chain_record(commitment_hex: str, data_did: str, owner_did: str,
                           fingerprint: str, signature_hex: str,
                           timestamp: str = None) -> dict:
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()
    rid = hashlib.sha256(
        f"{commitment_hex}{data_did}{timestamp}".encode()).hexdigest()[:32]
    return {
        "commitment": commitment_hex, "data_did": data_did,
        "owner_did": owner_did, "fingerprint": fingerprint,
        "timestamp": timestamp, "signature": signature_hex,
        "record_id": rid,
    }
