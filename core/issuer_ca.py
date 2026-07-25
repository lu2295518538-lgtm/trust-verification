"""
签发者可信体系 — 本地 PKI 信任锚
================================
现实里"电子出证"必须回答一个问题：这张《动物检疫合格证明》是谁签的、他有没有资格签、证有没有被作废。

本模块在沙箱内诚实实现 PKI 的核心结构（不对接外部商业 CA，但结构等价）：
    根 CA（自签）──签发──▶ 签发者证书
        证书绑定：DID ↔ 统一社会信用代码 ↔ 主体名称 ↔ SM2 公钥
        含：证书序列号、有效期(not_before/not_after)、状态(valid/revoked)
    验证 VC/VP 时：除密码学验签外，还要查"签发者是否在信任锚、证书是否有效、是否已被吊销"

所有密钥与证书持久化到 core/ca_store.json，重启 Flask 后信任锚不变（这是"可信"的前提）。
"""
import json
import os
from datetime import datetime, timezone, timedelta

from .sm2_sign import generate_keypair, sign_string, verify as sm2_verify
from .fingerprint import canonical_json

STORE_PATH = os.path.join(os.path.dirname(__file__), "ca_store.json")

ROOT_DID = "did:trust:livestock:root:ca"
ROOT_NAME = "畜牧检疫可信根证书颁发机构"
DEFAULT_ISSUER_DID = "did:trust:livestock:issuer:livestock_authority_001"

# 种子签发者（首次启动写入并持久化）
SEED_ISSUERS = [
    {"did": DEFAULT_ISSUER_DID, "name": "畜牧行业数据确权管理中心",
     "usc": "91110000MA01ABCDEF", "region": "全国", "role": "数据确权与权属发证"},
    {"did": "did:trust:livestock:issuer:vet_station_a", "name": "城西官方兽医检疫站",
     "usc": "91330100MA0C123456", "region": "杭州市", "role": "产地检疫出证"},
    {"did": "did:trust:livestock:issuer:slaughter_b", "name": "宏盛定点屠宰场",
     "usc": "91440300MA5D789012", "region": "深圳市", "role": "屠宰加工出证"},
]


def _utcnow():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.isoformat()


def _load_store():
    if os.path.exists(STORE_PATH):
        try:
            with open(STORE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return None


def _save_store(store):
    with open(STORE_PATH, "w", encoding="utf-8") as f:
        json.dump(store, f, ensure_ascii=False, indent=2)


class CAStore:
    """单例式信任锚：根 CA + 签发者注册表，持久化到磁盘。"""

    def __init__(self):
        store = _load_store()
        if store is None:
            store = self._bootstrap()
            _save_store(store)
        self._store = store

    # ---------- 初始化 ----------
    def _bootstrap(self):
        root = generate_keypair()
        issuers = {}
        year = _utcnow().year
        for i, s in enumerate(SEED_ISSUERS, start=1):
            kp = generate_keypair()
            nb = _utcnow()
            na = nb + timedelta(days=730)  # 证书有效期 2 年
            cert = {
                "serial": "CA-%d-%04d" % (year, i),
                "issuer_did": ROOT_DID,
                "subject": {
                    "did": s["did"], "name": s["name"],
                    "unified_social_credit_code": s["usc"],
                    "region": s["region"], "role": s["role"],
                },
                "public_key_x": kp["public_key_x"],
                "public_key_y": kp["public_key_y"],
                "private_key": kp["private_key"],
                "not_before": _iso(nb),
                "not_after": _iso(na),
                "status": "valid",
                "revoked_at": None,
                "revoke_reason": None,
            }
            cert["signature"] = self._sign_cert(root, cert)
            issuers[s["did"]] = cert
        return {
            "root": {
                "did": ROOT_DID, "name": ROOT_NAME,
                "public_key_x": root["public_key_x"],
                "public_key_y": root["public_key_y"],
                "private_key": root["private_key"],
            },
            "issuers": issuers,
        }

    @staticmethod
    def _cert_payload(cert):
        # 用于根 CA 签名/验签的规范化内容（不含 signature 自身）
        p = {k: v for k, v in cert.items() if k not in ("signature", "private_key")}
        return canonical_json(p)

    def _sign_cert(self, root, cert):
        sig = sign_string(self._cert_payload(cert), root["private_key"])
        return sig["signature"]

    # ---------- 查询 ----------
    def get_root(self):
        r = self._store["root"]
        return {"did": r["did"], "name": r["name"],
                "public_key_x": r["public_key_x"], "public_key_y": r["public_key_y"]}

    def get_cert(self, did):
        return self._store["issuers"].get(did)

    def get_issuer_private_key(self, did):
        c = self._store["issuers"].get(did)
        return c["private_key"] if c else None

    def list_issuers(self):
        return list(self._store["issuers"].values())

    def trusted_issuer_dids(self):
        """当前可信任的签发者 DID 列表（已注册 + 有效 + 未吊销 + 在有效期内）。"""
        now = _utcnow()
        out = []
        for c in self._store["issuers"].values():
            if c["status"] != "valid":
                continue
            try:
                if _utcnow().fromisoformat(c["not_after"]) < now:
                    continue
            except Exception:
                pass
            out.append(c["subject"]["did"])
        return out

    # ---------- 吊销 / 恢复 ----------
    def revoke(self, did, reason="管理员吊销"):
        c = self._store["issuers"].get(did)
        if not c:
            return False
        c["status"] = "revoked"
        c["revoked_at"] = _iso(_utcnow())
        c["revoke_reason"] = reason
        _save_store(self._store)
        return True

    def restore(self, did):
        c = self._store["issuers"].get(did)
        if not c:
            return False
        c["status"] = "valid"
        c["revoked_at"] = None
        c["revoke_reason"] = None
        _save_store(self._store)
        return True

    # ---------- 验证签发者 ----------
    def verify_issuer(self, did, pub_x=None, pub_y=None):
        """校验某签发者是否可信。

        返回 {trusted, status, reason, cert?}
            status: valid | revoked | expired | unknown | tampered | bad_cert
        """
        cert = self._store["issuers"].get(did)
        if not cert:
            return {"trusted": False, "status": "unknown",
                    "reason": "签发者不在信任锚（未注册）", "cert": None}
        # 公钥一致性（防篡改：VC 里嵌的公钥必须与注册表一致）
        if pub_x is not None and pub_y is not None:
            if pub_x != cert["public_key_x"] or pub_y != cert["public_key_y"]:
                return {"trusted": False, "status": "tampered",
                        "reason": "VC 内嵌公钥与注册表不符（疑似伪造）", "cert": cert}
        # 吊销
        if cert["status"] == "revoked":
            return {"trusted": False, "status": "revoked",
                    "reason": "签发者证书已被吊销：" + (cert.get("revoke_reason") or ""),
                    "cert": cert}
        # 有效期
        now = _utcnow()
        try:
            if _utcnow().fromisoformat(cert["not_before"]) > now:
                return {"trusted": False, "status": "expired",
                        "reason": "签发者证书尚未生效", "cert": cert}
            if _utcnow().fromisoformat(cert["not_after"]) < now:
                return {"trusted": False, "status": "expired",
                        "reason": "签发者证书已过期", "cert": cert}
        except Exception:
            return {"trusted": False, "status": "bad_cert",
                    "reason": "证书有效期格式异常", "cert": cert}
        # 证书签名（根 CA 验签）
        try:
            sig = cert.get("signature", "")
            if not sm2_verify(self._cert_payload(cert).encode(), sig[:64], sig[64:],
                              self._store["root"]["public_key_x"],
                              self._store["root"]["public_key_y"]):
                return {"trusted": False, "status": "bad_cert",
                        "reason": "证书根 CA 签名无效", "cert": cert}
        except Exception:
            return {"trusted": False, "status": "bad_cert",
                    "reason": "证书验签异常", "cert": cert}
        return {"trusted": True, "status": "valid",
                "reason": "签发者证书有效且在信任锚内", "cert": cert}


# 全局单例
ca_store = CAStore()
