"""
任务一：数据完整性确权 — SM3 指纹 + Canonical JSON
"""
import json
import hashlib
from typing import Tuple, Optional

def canonical_json(obj: dict) -> str:
    """键排序 + 无空格 + 固定浮点精度，保证多次序列化一致"""
    def _sort(o):
        if isinstance(o, dict):
            return {k: _sort(v) for k, v in sorted(o.items())}
        elif isinstance(o, list):
            return [_sort(i) for i in o]
        elif isinstance(o, float):
            return round(o, 10)
        return o
    return json.dumps(_sort(obj), ensure_ascii=False, separators=(',', ':'), sort_keys=True)

# ── SM3 国密哈希（纯 Python）──
def sm3_hash(data: bytes) -> str:
    IV = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
          0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]
    T = [0x79CC4519] * 16 + [0x7A879D8A] * 48

    def rotl(x, n): return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    def p0(x): return x ^ rotl(x, 9) ^ rotl(x, 17)
    def p1(x): return x ^ rotl(x, 15) ^ rotl(x, 23)
    def ff(x, y, z, j): return x ^ y ^ z if j < 16 else (x & y) | (x & z) | (y & z)
    def gg(x, y, z, j): return x ^ y ^ z if j < 16 else (x & y) | ((~x & 0xFFFFFFFF) & z)

    data_len = len(data)
    data = bytearray(data)
    data.append(0x80)
    while len(data) % 64 != 56:
        data.append(0)
    data += (data_len * 8).to_bytes(8, 'big')

    v = list(IV)
    for i in range(0, len(data), 64):
        block = data[i:i+64]
        w = [int.from_bytes(block[j*4:(j+1)*4], 'big') for j in range(16)]
        for j in range(16, 68):
            w.append(p1(w[j-16] ^ w[j-9] ^ rotl(w[j-3], 15)) ^ rotl(w[j-13], 7) ^ w[j-6])
        w1 = [w[j] ^ w[j+4] for j in range(64)]
        a, b, c, d, e, f, g, h = v
        for j in range(64):
            ss1 = rotl((rotl(a, 12) + e + rotl(T[j], j % 32)) & 0xFFFFFFFF, 7)
            ss2 = ss1 ^ rotl(a, 12)
            tt1 = (ff(a, b, c, j) + d + ss2 + w1[j]) & 0xFFFFFFFF
            tt2 = (gg(e, f, g, j) + h + ss1 + w[j]) & 0xFFFFFFFF
            d, c, b, a = c, rotl(b, 9), a, tt1
            h, g, f, e = g, rotl(f, 19), e, p0(tt2)
        v = [(v[k] ^ x) & 0xFFFFFFFF for k, x in enumerate([a, b, c, d, e, f, g, h])]
    return ''.join(f'{x:08x}' for x in v)

def sm3_hash_string(s: str) -> str:
    return sm3_hash(s.encode('utf-8'))

def sha256_hash_string(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def generate_fingerprint(raw_data: str, metadata: dict, algorithm: str = "SM3",
                         confidence: Optional[float] = None) -> dict:
    normalized = canonical_json(metadata)
    combined = raw_data + normalized
    if algorithm.upper() == "SM3":
        fp = sm3_hash_string(combined)
    else:
        fp = sha256_hash_string(combined)
    need_review = (confidence is not None and confidence < 0.85)
    return {
        "fingerprint": fp, "algorithm": algorithm.upper(),
        "metadata_json": normalized, "confidence": confidence,
        "need_review": need_review,
    }

def verify_fingerprint(raw_data: str, metadata: dict,
                       expected_fp: str, algorithm: str = "SM3") -> bool:
    return generate_fingerprint(raw_data, metadata, algorithm)["fingerprint"] == expected_fp
