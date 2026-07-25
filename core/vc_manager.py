# -*- coding: utf-8 -*-
"""
DID 身份核验 — VC/VP 可验证凭证体系（重构：对齐 DID_test 参考实现）

构造法（与参考文件一致）：
  - 元数据按 basic / ownership / content 三模块组织（模块化选择性披露）
  - 三元组哈希  x = SHA256(metadata_json || fingerprint || did)
  - P-256 上 Pedersen 承诺  C = x·G + r·H
  - 全披露：携带明文 selected_data + 盲因子 r + triple_hash_x
  - 零知识：仅携带 commitment(Cx,Cy) + Schnorr ZKP，不泄露任何明文

保留项（参考文件未含，本系统既有可信闭环）：
  - 签发者 CA 信任锚 + SM2 签名信封（proof）。参考实现无签发者问责，
    本系统在 VP/VC 外层附加发行方签名与 CA 校验，使"谁签发"可问责。
"""

import json
import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any

from .fingerprint import canonical_json
from .sm2_sign import generate_keypair, sign_string, verify as sm2_verify
from .issuer_ca import ca_store
from .pedersen_zkp import pedersen_commit, compute_triple_hash, normalize_metadata, SchnorrZKP

ISSUER_KEYPAIR = generate_keypair()
ISSUER_DID = "did:trust:livestock:issuer:livestock_authority_001"
ISSUER_NAME = "畜牧行业数据确权管理中心"

MODULES_ALL = ["basic", "ownership", "content"]


# ========== 多发行方注册中心（兼容保留） ==========
class IssuerRegistry:
    def __init__(self):
        self._issuers: Dict[str, Dict] = {}

    def register(self, issuer_did, name, public_key_x, public_key_y):
        self._issuers[issuer_did] = {
            "issuer_did": issuer_did, "name": name,
            "public_key_x": public_key_x, "public_key_y": public_key_y,
        }

    def get(self, issuer_did):
        return self._issuers.get(issuer_did)

    def list_all(self):
        return list(self._issuers.values())


issuer_registry = IssuerRegistry()
issuer_registry.register(
    ISSUER_DID, ISSUER_NAME,
    ISSUER_KEYPAIR["public_key_x"], ISSUER_KEYPAIR["public_key_y"]
)


def _signable_json(vc):
    """生成用于 SM2 签名的规范化字节：剔除 proof，并剔除 credentialSubject.selected_data
    （明文披露载荷不进入签名域，以便零知识 VP 可剥离明文而不失效——真正最小披露）。"""
    v = {k: val for k, val in vc.items() if k != "proof"}
    subj = v.get("credentialSubject")
    if isinstance(subj, dict) and "selected_data" in subj:
        subj = {k: val for k, val in subj.items() if k != "selected_data"}
        v = {**v, "credentialSubject": subj}
    return canonical_json(v)


def request_credential(metadata, holder_did, issuer_did=None, issuer_name=None,
                       modules=None, use_zk=False, validity_days=365):
    """
    申请数据权属可验证凭证（VC）。

    构造：归一化三模块元数据 → 指纹 → 三元组哈希 x → P-256 Pedersen 承诺
          → 生成 credentialSubject（全披露携带 r/x，零知识携带 Schnorr ZKP）
          → 发行方用自有 SM2 密钥签名（CA 信任锚内、有效且未吊销）。
    """
    if not issuer_did:
        issuer_did = ISSUER_DID
    if issuer_name is None:
        issuer_name = ISSUER_NAME

    # 发行方必须已在 CA 信任锚注册、有效、未吊销，且用其自有密钥签名
    _cert = ca_store.get_cert(issuer_did)
    if not _cert:
        raise ValueError("签发者 DID 未在信任锚注册，拒绝签发: " + str(issuer_did))
    if _cert["status"] != "valid":
        raise ValueError("签发者证书状态异常（%s），拒绝签发" % _cert["status"])
    issuer_name = _cert["subject"]["name"]
    _sign_priv = ca_store.get_issuer_private_key(issuer_did)

    if not holder_did:
        raise ValueError("持证人 DID 不能为空")

    norm = normalize_metadata(metadata, holder_did)
    if not modules:
        modules = list(MODULES_ALL)
    selected = {m: norm[m] for m in modules if m in norm}

    data_id = norm["basic"].get("data_id") or selected.get("basic", {}).get("data_id")
    if not data_id:
        data_id = "data-" + hashlib.sha256(
            json.dumps(selected, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:20]

    # 指纹 = SHA256(selected_data)；三元组哈希 x = SHA256(metadata || fp || did)
    combined = json.dumps(selected, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    fingerprint = hashlib.sha256(combined.encode("utf-8")).hexdigest()
    x = compute_triple_hash(selected, fingerprint, holder_did)

    cx, cy, r = pedersen_commit(x)

    subject = {
        "id": holder_did,
        "data_id": data_id,
        "modules": modules,
        "fingerprint": fingerprint,
        "pedersen_commitment": {"cx": cx, "cy": cy},
        "selected_data": selected,
    }
    if use_zk:
        zkp = SchnorrZKP().prove(x_hex=x, r_hex=r, did=holder_did, Cx_hex=cx, Cy_hex=cy)
        subject["zk_proof"] = {
            "type": "SchnorrPedersen",
            "T": {"x": zkp["T_x"], "y": zkp["T_y"]},
            "z_x": zkp["z_x"], "z_r": zkp["z_r"],
        }
    else:
        subject["blinding_factor_r"] = r
        subject["triple_hash_x"] = x

    issuance = datetime.now(timezone.utc).isoformat()
    expiration = None
    if validity_days and validity_days > 0:
        expiration = (datetime.now(timezone.utc) + timedelta(days=validity_days)).isoformat()

    vc = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential", "LivestockDataOwnershipCredential"],
        "id": "vc:" + hashlib.sha256((holder_did + data_id + issuance).encode()).hexdigest()[:16],
        "issuer": {"id": issuer_did, "name": issuer_name},
        "issuanceDate": issuance,
        "credentialSubject": subject,
        "expirationDate": expiration,
    }
    # 仅对"不含明文的承诺绑定结构"签名：selected_data 作为可剥离的披露载荷，
    # 不进入签名域——零知识 VP 可剔除明文而不破坏发行方签名（真正最小披露）。
    vc_json = _signable_json(vc)
    sig = sign_string(vc_json, _sign_priv)
    vc["proof"] = {
        "type": "SM2Signature2024", "created": issuance,
        "verificationMethod": issuer_did + "#keys-1",
        "proofPurpose": "assertionMethod", "proofValue": sig["signature"],
        "certSerial": _cert["serial"],
        "issuerPublicKey": {"x": _cert["public_key_x"], "y": _cert["public_key_y"]},
    }
    return vc


def verify_credential(vc):
    """验证 VC：① 发行方 SM2 签名 + CA 信任锚 ② Pedersen 承诺 / Schnorr ZKP 校验。"""
    errors = []
    proof = vc.get("proof", {})
    subject = vc.get("credentialSubject", {})

    # ---- ① 发行方签名 + CA 信任锚 ----
    pub_x = proof.get("issuerPublicKey", {}).get("x")
    pub_y = proof.get("issuerPublicKey", {}).get("y")
    proof_value = proof.get("proofValue", "")
    issuer_trusted = False
    issuer_status = "unknown"
    if not pub_x or not pub_y or not proof_value:
        errors.append("proof 不完整")
    else:
        vc_json = _signable_json(vc)  # 与签发时一致：剔除 proof 与明文 selected_data
        if not sm2_verify(vc_json.encode(), proof_value[:64], proof_value[64:], pub_x, pub_y):
            errors.append("发行方签名验证失败")
        _iss_did = vc.get("issuer", {}).get("id", "")
        _trust = ca_store.verify_issuer(_iss_did, pub_x, pub_y)
        issuer_trusted = _trust["trusted"]
        issuer_status = _trust["status"]
        if not issuer_trusted:
            errors.append("签发者不可信：" + _trust["reason"])
        # vc_json 由 _signable_json 生成：与签发时一致，剔除 proof 与明文 selected_data

    # ---- ② 承诺 / ZK 校验 ----
    commitment_valid = False
    zk_verified = False
    mode = None
    try:
        holder_did = subject.get("id") or subject.get("ownership", {}).get("did") or ""
        selected = subject.get("selected_data", {})
        fingerprint = subject.get("fingerprint", "")
        comm = subject.get("pedersen_commitment", {})
        cx = comm.get("cx")
        cy = comm.get("cy")
        if not holder_did or not cx or not cy:
            errors.append("凭证缺少必要字段（id / 承诺坐标）")
        elif subject.get("zk_proof"):
            mode = "zk_only"
            zk = subject["zk_proof"]
            zk_verified = SchnorrZKP().verify(
                did=holder_did, Cx_hex=cx, Cy_hex=cy,
                proof={"T_x": zk["T"]["x"], "T_y": zk["T"]["y"],
                       "z_x": zk["z_x"], "z_r": zk["z_r"]})
            commitment_valid = zk_verified
            if not zk_verified:
                errors.append("Schnorr 零知识证明验证失败")
        elif "blinding_factor_r" in subject and "triple_hash_x" in subject:
            mode = "full"
            # 关键：从（可能被篡改的）selected_data 重新计算三元组哈希 x，
            # 再与 VC 中存储的 triple_hash_x 比对——若明文被改，x 必然不一致。
            # 对齐参考 main.py 的 verify_vp：x = compute_triple_hash(selected_data, fingerprint, did)
            try:
                x_recomputed = compute_triple_hash(selected, fingerprint, holder_did)
            except Exception as e:
                errors.append("三元组哈希重算异常：" + str(e))
                x_recomputed = None
            if x_recomputed is None or x_recomputed != subject.get("triple_hash_x"):
                commitment_valid = False
                errors.append("明文数据与原始承诺不一致（凭证可能已被篡改）")
            else:
                cx_calc, cy_calc, _ = pedersen_commit(x_recomputed, subject["blinding_factor_r"])
                commitment_valid = (cx_calc == cx and cy_calc == cy)
                if not commitment_valid:
                    errors.append("Pedersen 承诺校验失败（明文/盲因子不匹配）")
        else:
            errors.append("凭证既无盲因子也无 ZK 证明，无法校验承诺")
    except Exception as e:
        errors.append("承诺校验异常：" + str(e))

    # ---- 过期检查 ----
    expiration = vc.get("expirationDate")
    if expiration:
        try:
            if datetime.fromisoformat(expiration) < datetime.now(timezone.utc):
                errors.append("VC 已过期")
        except (ValueError, TypeError):
            pass

    return {
        "valid": len(errors) == 0,
        "issuer": vc.get("issuer", {}).get("id", ""),
        "issuer_name": vc.get("issuer", {}).get("name", ""),
        "issuer_trusted": issuer_trusted,
        "issuer_status": issuer_status,
        "issuer_cert_serial": (vc.get("proof", {}) or {}).get("certSerial"),
        "owner": subject.get("id", ""),
        "owner_name": subject.get("ownership", {}).get("owner")
                     or subject.get("basic", {}).get("data_name") or "",
        "mode": mode,
        "commitment_valid": commitment_valid,
        "zk_verified": zk_verified,
        "data_id": subject.get("data_id", ""),
        "modules": subject.get("modules", []),
        "errors": errors,
    }


def construct_presentation(vc, modules=None, challenge=None, domain=None):
    """构造可验证表达（VP）：包裹 VC，按披露模式生成。零知识模式下不携带明文。"""
    if not vc or not isinstance(vc, dict) or not vc.get("credentialSubject"):
        return {"error": "无效的 VC 数据", "id": "vp:error",
                "type": ["VerifiablePresentation"], "holder": "",
                "verifiableCredential": []}

    if challenge is None:
        challenge = hashlib.sha256(secrets.token_bytes(16)).hexdigest()[:16]

    subject = vc.get("credentialSubject", {})
    holder = subject.get("id", "")
    disclosure = "zk_only" if subject.get("zk_proof") else "full"

    embedded_vc = vc
    if disclosure == "zk_only":
        # 真正最小披露：零知识 VP 剔除明文 selected_data，仅保留承诺 + Schnorr ZKP。
        # 发行方签名域本就不含 selected_data，故剥离后签名依然有效。
        ev = {k: val for k, val in vc.items() if k != "proof"}
        esubj = {k: val for k, val in ev.get("credentialSubject", {}).items()
                 if k != "selected_data"}
        ev = {**ev, "credentialSubject": esubj, "proof": vc.get("proof")}
        embedded_vc = ev

    vp = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": "VerifiablePresentation",
        "id": "vp:" + hashlib.sha256((vc.get("id", "") + challenge).encode()).hexdigest()[:16],
        "holder": holder,
        "disclosure": disclosure,
        "modules": subject.get("modules", []),
        "created": datetime.now(timezone.utc).isoformat(),
        "verifiableCredential": [embedded_vc],
        "challenge": challenge,
        "domain": domain,
    }
    return vp


def verify_presentation(vp):
    """验证 VP：逐张校验内嵌 VC（含承诺/ZK 与签发者信任），并核对持有者一致性。"""
    if not vp or not isinstance(vp, dict):
        return {"valid": False, "holder": "", "errors": ["VP 为空或格式错误"],
                "verdict": "权属验证失败"}
    errors = []
    holder = vp.get("holder", "")
    disc = vp.get("disclosure")
    vc_results = []
    for vc in vp.get("verifiableCredential", []):
        vcr = verify_credential(vc)
        vc_results.append(vcr)
        if not vcr["valid"]:
            errors.append("VC 验证失败: " + "; ".join(vcr["errors"]))
        if vcr.get("owner") and holder and vcr.get("owner") != holder:
            errors.append("VC 权属人(%s) 与 VP 持有者(%s) 不一致" % (vcr.get("owner"), holder))

    for vcr in vc_results:
        if disc == "zk_only" and vcr.get("mode") != "zk_only":
            errors.append("VP 声明零知识但内嵌 VC 未含 ZK 证明")
        if disc == "full" and vcr.get("mode") != "full":
            errors.append("VP 声明全披露但内嵌 VC 含 ZK 证明")

    return {
        "valid": len(errors) == 0,
        "holder": holder,
        "mode": disc,
        "did": holder,
        "modules": vp.get("modules", []),
        "issuer_status": (vc_results[0].get("issuer_status") if vc_results else None),
        "issuer_trusted": (vc_results[0].get("issuer_trusted") if vc_results else False),
        "verdict": ("权属验证通过 — 数据所有者身份已确认（" + (disc or "unknown") + "）")
                   if len(errors) == 0 else "权属验证失败",
        "vc_verification": vc_results,
        "errors": errors,
    }


def get_issuer_info():
    _cert = ca_store.get_cert(ISSUER_DID)
    _root = ca_store.get_root()
    return {
        "issuer_did": ISSUER_DID, "issuer_name": ISSUER_NAME,
        "public_key_x": (_cert or {}).get("public_key_x", ISSUER_KEYPAIR["public_key_x"]),
        "public_key_y": (_cert or {}).get("public_key_y", ISSUER_KEYPAIR["public_key_y"]),
        "cert_serial": (_cert or {}).get("serial"),
        "cert_status": (_cert or {}).get("status", "unknown"),
        "root_did": _root["did"], "root_name": _root["name"],
    }


def get_ca_directory():
    """返回根 CA + 全部签发者证书目录（供前端"签发者目录"展示）。"""
    root = ca_store.get_root()
    issuers = []
    for c in ca_store.list_issuers():
        issuers.append({
            "did": c["subject"]["did"], "name": c["subject"]["name"],
            "unified_social_credit_code": c["subject"]["unified_social_credit_code"],
            "region": c["subject"]["region"], "role": c["subject"]["role"],
            "serial": c["serial"], "status": c["status"],
            "not_before": c["not_before"], "not_after": c["not_after"],
            "revoked_at": c.get("revoked_at"), "revoke_reason": c.get("revoke_reason"),
            "public_key_x": c["public_key_x"], "public_key_y": c["public_key_y"],
        })
    return {"root": root, "issuers": issuers}
