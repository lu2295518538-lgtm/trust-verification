# -*- coding: utf-8 -*-
"""
Pedersen 承诺 + Schnorr 零知识证明（NIST P-256，使用 ecdsa 库）

直接对齐 DID_test 参考实现（main.py 中的 PedersenCommitment / SchnorrZKP）：
    x          = SHA256(metadata_json || fingerprint || did)      # 三元组哈希
    C = x·G + r·H                                                  # P-256 上的 Pedersen 承诺
    ZK 证明     = Schnorr Σ 协议，证明持有 (x, r) 而不泄露任何明文   # 零知识选择性披露
"""
import hashlib
import json
import secrets

from ecdsa import NIST256p
from ecdsa.ellipticcurve import Point


def compute_triple_hash(metadata, fingerprint, did):
    """三元组哈希 x = SHA256(metadata_json || fingerprint || did)。"""
    if isinstance(metadata, dict):
        metadata_str = json.dumps(metadata, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    else:
        metadata_str = str(metadata)
    concat = (metadata_str + fingerprint + did).encode("utf-8")
    return hashlib.sha256(concat).hexdigest()


class PedersenCommitment:
    """Pedersen 承诺：C = x·G + r·H（P-256 曲线）"""

    def __init__(self):
        self.curve = NIST256p
        self.G = self.curve.generator
        self.H = self._generate_H()

    def _generate_H(self):
        seed = b"PEDERSEN_H_SECOND_BASE_POINT"
        for i in range(256):
            h = hashlib.sha256(seed + bytes([i])).digest()
            x = int.from_bytes(h, "big") % self.curve.curve.p()
            try:
                point = Point.from_bytes(self.curve.curve, b"\x02" + x.to_bytes(32, "big"))
                return point
            except Exception:
                continue
        raise RuntimeError("无法生成 H 点")

    def commit(self, x_hex, r_hex=None):
        x_int = int.from_bytes(bytes.fromhex(x_hex), "big")
        if r_hex is None:
            r_int = secrets.randbits(256)
            r_hex = r_int.to_bytes(32, "big").hex()
        else:
            r_int = int.from_bytes(bytes.fromhex(r_hex), "big")
        C = self.G * x_int + self.H * r_int
        return format(C.x(), "x"), format(C.y(), "x"), r_hex


class SchnorrZKP:
    """Schnorr-like Σ 协议 for Pedersen Commitment"""

    def __init__(self, pedersen=None):
        if pedersen is None:
            pedersen = PedersenCommitment()
        self.curve = pedersen.curve
        self.G = pedersen.G
        self.H = pedersen.H
        self.n = self.curve.order

    def _hash_to_scalar(self, *args) -> int:
        h_input = b"||".join(
            arg.to_bytes(32, "big") if isinstance(arg, int)
            else str(arg).encode("utf-8")
            for arg in args
        )
        h = hashlib.sha256(h_input).digest()
        return int.from_bytes(h, "big") % self.n

    def prove(self, x_hex, r_hex, did, Cx_hex, Cy_hex) -> dict:
        x = int.from_bytes(bytes.fromhex(x_hex), "big")
        r = int.from_bytes(bytes.fromhex(r_hex), "big")
        Cx = int(Cx_hex, 16)
        Cy = int(Cy_hex, 16)

        s_x = secrets.randbelow(self.n - 1) + 1
        s_r = secrets.randbelow(self.n - 1) + 1

        T = self.G * s_x + self.H * s_r
        c = self._hash_to_scalar(Cx, Cy, T.x(), T.y(), did)
        z_x = (s_x + c * x) % self.n
        z_r = (s_r + c * r) % self.n

        return {
            "T_x": format(T.x(), "x"),
            "T_y": format(T.y(), "x"),
            "z_x": format(z_x, "x"),
            "z_r": format(z_r, "x"),
        }

    def verify(self, did, Cx_hex, Cy_hex, proof) -> bool:
        T_x = int(proof["T_x"], 16)
        T_y = int(proof["T_y"], 16)
        z_x = int(proof["z_x"], 16)
        z_r = int(proof["z_r"], 16)
        Cx = int(Cx_hex, 16)
        Cy = int(Cy_hex, 16)

        T = Point(self.curve.curve, T_x, T_y)
        C = Point(self.curve.curve, Cx, Cy)

        c_prime = self._hash_to_scalar(Cx, Cy, T_x, T_y, did)

        left = self.G * z_x + self.H * z_r
        right = T + C * c_prime

        return left.x() == right.x() and left.y() == right.y()


def pedersen_commit(x_hex, r_hex=None):
    """模块级便捷封装：C = x·G + r·H，返回 (cx, cy, r_hex)。"""
    return PedersenCommitment().commit(x_hex, r_hex)


# ===================== 畜牧领域元数据三模块归一化 =====================
MODULE_FIELDS = {
    "basic": ["data_id", "data_type", "data_name", "version", "created_at"],
    "ownership": ["owner", "org_id", "did", "license"],
    "content": ["fingerprint", "file_size", "file_type", "description", "tags"],
}


def normalize_metadata(metadata, did=""):
    """将前端传入的（可能扁平的）元数据规范化为 basic / ownership / content 三模块。"""
    if not isinstance(metadata, dict):
        metadata = {}
    m = {k: dict(v) for k, v in metadata.items() if k in MODULE_FIELDS}
    flat = {k: v for k, v in metadata.items() if k not in MODULE_FIELDS}

    basic = m.get("basic", {})
    ownership = m.get("ownership", {})
    content = m.get("content", {})

    for src, dst, key in (
        ("data_id", basic, "data_id"), ("检疫编号", basic, "data_id"),
        ("data_type", basic, "data_type"), ("data_name", basic, "data_name"),
        ("name", basic, "data_name"),
        ("owner", ownership, "owner"), ("org_id", ownership, "org_id"),
        ("license", ownership, "license"),
        ("fingerprint", content, "fingerprint"), ("description", content, "description"),
        ("tags", content, "tags"),
    ):
        if src in flat and key not in dst:
            dst[key] = flat[src]

    ownership["did"] = did or ownership.get("did", "")
    basic.setdefault("version", "1.0")
    if not basic.get("created_at"):
        from datetime import datetime, timezone
        basic["created_at"] = datetime.now(timezone.utc).isoformat()
    if not basic.get("data_id"):
        basic["data_id"] = "data-" + hashlib.sha256(
            json.dumps(flat, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:20]
    content.setdefault("file_size", 0)
    content.setdefault("file_type", basic.get("data_type", ""))
    if not isinstance(content.get("tags"), list):
        content["tags"] = []

    return {"basic": basic, "ownership": ownership, "content": content}
