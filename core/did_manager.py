"""
W3C DID 管理 + 链上存证记录
"""
import hashlib
import time
from datetime import datetime, timezone
from core.fingerprint import canonical_json

DID_PREFIX = "did:trust:livestock"
# 统一命名空间：所有主体/签发者 DID 均以 did:trust:livestock 为根，
# 主体 DID 结构为 did:trust:livestock:party:<issuer_id>:<short>
# —— 把"由哪个签发机构背书"直接编码进 DID，实现强绑定（而非名称软匹配）。
ENTITY_PARTY = "party"
ENTITY_ISSUER = "issuer"

def generate_did(entity_type: str = "data", seed: str = None,
                 issuer: str = None, short: str = None) -> dict:
    """生成 DID。
    - 默认（无 issuer）：did:trust:livestock:<entity_type>:<sid>
    - 当 entity_type 为 owner/party 且给定 issuer 时：
        did:trust:livestock:<entity_type>:<issuer>:<short or sid>
      即把背书签发机构 id 直接嵌入 DID，构成强绑定命名空间。
    """
    if seed is None:
        seed = __import__('os').urandom(32).hex()
    sid = hashlib.sha256(f"{entity_type}:{seed}:{time.time()}".encode()).hexdigest()[:32]
    if entity_type in (ENTITY_PARTY, "owner") and issuer:
        suffix = short or sid
        did = f"{DID_PREFIX}:{entity_type}:{issuer}:{suffix}"
    else:
        did = f"{DID_PREFIX}:{entity_type}:{sid}"
    return {
        "did": did,
        "entity_type": entity_type,
        "issuer_id": issuer,
        "specific_id": short or sid,
        "created": datetime.now(timezone.utc).isoformat(),
    }

def party_did(issuer_id: str, short: str) -> str:
    """强绑定主体 DID：did:trust:livestock:party:<issuer_id>:<short>。"""
    return f"{DID_PREFIX}:{ENTITY_PARTY}:{issuer_id}:{short}"

def issuer_did(issuer_id: str) -> str:
    """签发机构 DID：did:trust:livestock:issuer:<issuer_id>。"""
    return f"{DID_PREFIX}:{ENTITY_ISSUER}:{issuer_id}"

def parse_did(did: str) -> dict:
    """健壮解析 DID，返回分段信息；非法 DID 各字段为空。"""
    parts = (did or "").split(":")
    return {
        "prefix": parts[0] if len(parts) > 0 else "",
        "ns": parts[1] if len(parts) > 1 else "",
        "entity": parts[2] if len(parts) > 2 else "",
        "sub": parts[3] if len(parts) > 3 else "",
        "id1": parts[4] if len(parts) > 4 else "",
        "id2": parts[5] if len(parts) > 5 else "",
        "segments": parts,
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
