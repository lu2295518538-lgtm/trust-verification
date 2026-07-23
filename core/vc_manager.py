"""
DID 身份核验 — VC/VP 可验证凭证体系
VC申请 → VP构造(选择性披露) → VP验证(权属确认)
支持VC过期机制与多发行方注册
"""
import json, hashlib, time
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict
from .fingerprint import canonical_json
from .sm2_sign import generate_keypair, sign_string, verify as sm2_verify

ISSUER_KEYPAIR = generate_keypair()
ISSUER_DID = "did:trust:livestock:issuer:livestock_authority_001"
ISSUER_NAME = "畜牧行业数据确权管理中心"


# ========== 多发行方注册中心 ==========

class IssuerRegistry:
    """
    发行方注册中心 — 管理多个可信发行方的身份信息。

    支持注册、查询和列出所有发行方，用于VC签发时选择发行方身份。
    """

    def __init__(self):
        self._issuers: Dict[str, Dict] = {}

    def register(self, issuer_did: str, name: str, public_key_x: str, public_key_y: str):
        """注册一个新的发行方"""
        self._issuers[issuer_did] = {
            "issuer_did": issuer_did,
            "name": name,
            "public_key_x": public_key_x,
            "public_key_y": public_key_y,
        }

    def get(self, issuer_did: str) -> Optional[Dict]:
        """根据DID获取发行方信息，不存在返回None"""
        return self._issuers.get(issuer_did)

    def list_all(self) -> List[Dict]:
        """列出所有已注册的发行方"""
        return list(self._issuers.values())


# 全局发行方注册中心实例，初始化时注册默认发行方
issuer_registry = IssuerRegistry()
issuer_registry.register(
    ISSUER_DID, ISSUER_NAME,
    ISSUER_KEYPAIR["public_key_x"], ISSUER_KEYPAIR["public_key_y"]
)

def request_credential(owner_did, owner_name, data_did, fingerprint,
                       data_type, on_chain_tx, issuer_did=None, issuer_name=None,
                       validity_days=365):
    """
    申请针对该数据资产的可验证凭证（VC）

    参数:
        validity_days: VC有效期天数，默认365天。设为None或0则不设置过期时间。
        issuer_did: 指定发行方DID，不传则使用默认发行方
        issuer_name: 指定发行方名称，不传则使用默认发行方名称
    """
    if issuer_did is None: issuer_did = ISSUER_DID
    if issuer_name is None: issuer_name = ISSUER_NAME

    # 尝试从注册中心获取发行方密钥对（用于签名）
    issuer_info = issuer_registry.get(issuer_did)
    if issuer_info:
        issuer_name = issuer_info["name"]

    issuance_date = datetime.now(timezone.utc).isoformat()

    # 计算过期时间
    expiration_date = None
    if validity_days and validity_days > 0:
        expiration_date = (datetime.now(timezone.utc) + timedelta(days=validity_days)).isoformat()

    vc = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential", "LivestockDataOwnershipCredential"],
        "id": "vc:" + hashlib.sha256((owner_did + data_did + issuance_date).encode()).hexdigest()[:16],
        "issuer": {"id": issuer_did, "name": issuer_name},
        "issuanceDate": issuance_date,
        "credentialSubject": {
            "id": owner_did, "name": owner_name,
            "dataAsset": {"id": data_did, "fingerprint": fingerprint,
                          "dataType": data_type, "onChainRecord": on_chain_tx},
        },
        "expirationDate": expiration_date,
    }
    vc_json = canonical_json(vc)
    sig = sign_string(vc_json, ISSUER_KEYPAIR["private_key"])
    vc["proof"] = {
        "type": "SM2Signature2024", "created": issuance_date,
        "verificationMethod": f"{issuer_did}#keys-1",
        "proofPurpose": "assertionMethod", "proofValue": sig["signature"],
        "issuerPublicKey": {"x": ISSUER_KEYPAIR["public_key_x"],
                            "y": ISSUER_KEYPAIR["public_key_y"]},
    }
    return vc

def verify_credential(vc):
    """验证 VC 有效性（包括签名验证和过期检查）"""
    errors = []
    proof = vc.get("proof", {})
    if not proof: return {"valid": False, "errors": ["缺失 proof"]}
    pub_x = proof.get("issuerPublicKey", {}).get("x")
    pub_y = proof.get("issuerPublicKey", {}).get("y")
    proof_value = proof.get("proofValue", "")
    if not pub_x or not pub_y or not proof_value:
        return {"valid": False, "errors": ["proof 不完整"]}

    # 过期检查：如果设置了 expirationDate 则验证是否已过期
    expiration_date_str = vc.get("expirationDate")
    if expiration_date_str:
        try:
            exp_date = datetime.fromisoformat(expiration_date_str)
            if datetime.now(timezone.utc) > exp_date:
                errors.append(f"VC已过期，过期时间: {expiration_date_str}")
        except (ValueError, TypeError):
            errors.append("expirationDate 格式无效")

    vc_unsigned = {k: v for k, v in vc.items() if k != "proof"}
    vc_json = canonical_json(vc_unsigned)
    if not sm2_verify(vc_json.encode(), proof_value[:64], proof_value[64:], pub_x, pub_y):
        errors.append("发行方签名验证失败")
    subject = vc.get("credentialSubject", {})
    asset = subject.get("dataAsset", {})
    return {
        "valid": len(errors) == 0,
        "issuer": vc.get("issuer", {}).get("id", ""),
        "issuer_name": vc.get("issuer", {}).get("name", ""),
        "owner": subject.get("id", ""),
        "owner_name": subject.get("name", ""),
        "asset": {"data_did": asset.get("id", ""), "fingerprint": asset.get("fingerprint", ""),
                  "data_type": asset.get("dataType", ""), "on_chain_record": asset.get("onChainRecord", "")},
        "issuance_date": vc.get("issuanceDate", ""),
        "expiration_date": expiration_date_str,
        "errors": errors,
    }

def construct_presentation(vc, owner_private_key, owner_public_key_x,
                           owner_public_key_y, disclose_fields=None, hide_fields=None, challenge=None):
    """选择性披露身份信息，构造可验证呈现（VP）。

    前置条件: vc 必须是有效的 VC 对象，包含 credentialSubject 和 proof。
    如果 vc 为空或不完整，返回包含错误信息的 dict（而非抛出异常）。
    """
    if not vc or not isinstance(vc, dict) or not vc.get("credentialSubject"):
        return {
            "error": "无效的 VC 数据",
            "id": "vp:error",
            "type": ["VerifiablePresentation"],
            "holder": "",
            "verifiableCredential": [],
        }

    if disclose_fields is None: disclose_fields = ["name", "dataType"]
    if hide_fields is None: hide_fields = []
    if challenge is None: challenge = hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]

    subject = vc.get("credentialSubject", {})
    asset = subject.get("dataAsset", {})
    disclosed_subject = {"id": subject.get("id", "")}
    if "name" in disclose_fields and "name" not in hide_fields:
        disclosed_subject["name"] = subject.get("name", "***")
    disclosed_asset = {"id": asset.get("id", "")}
    for field in ["dataType", "fingerprint"]:
        if field in disclose_fields and field not in hide_fields:
            disclosed_asset[field] = asset.get(field, "***")
    disclosed_subject["dataAsset"] = disclosed_asset

    vp = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiablePresentation"],
        "id": "vp:" + hashlib.sha256((vc.get('id', '') + challenge).encode()).hexdigest()[:16],
        "holder": subject.get("id", ""),
        "verifiableCredential": [vc],
        "disclosedClaims": disclosed_subject,
        "disclosurePolicy": {"disclose": disclose_fields, "hide": hide_fields},
        "challenge": challenge,
        "created": datetime.now(timezone.utc).isoformat(),
    }
    vp_json = canonical_json({k: v for k, v in vp.items() if k != "proof"})
    sig = sign_string(vp_json, owner_private_key)
    vp["proof"] = {
        "type": "SM2Signature2024", "created": datetime.now(timezone.utc).isoformat(),
        "verificationMethod": f"{subject.get('id', '')}#keys-1",
        "proofPurpose": "authentication", "proofValue": sig["signature"],
        "holderPublicKey": {"x": owner_public_key_x, "y": owner_public_key_y},
    }
    return vp

def verify_presentation(vp, trusted_issuers=None):
    """验证者校验 VP 有效性，确认数据权属（包含VC过期检查）。

    如果 VP 为空或不完整，返回失败结果而非抛出异常。
    """
    if not vp or not isinstance(vp, dict):
        return {"valid": False, "holder": "", "disclosed": {}, "errors": ["VP 数据为空或格式错误"], "verdict": "权属验证失败"}
    if trusted_issuers is None: trusted_issuers = [ISSUER_DID]
    errors = []
    vp_proof = vp.get("proof", {})
    vp_pub_x = vp_proof.get("holderPublicKey", {}).get("x")
    vp_pub_y = vp_proof.get("holderPublicKey", {}).get("y")
    vp_proof_value = vp_proof.get("proofValue", "")
    if not vp_pub_x or not vp_pub_y or not vp_proof_value:
        errors.append("VP proof 不完整")
    else:
        vp_unsigned = {k: v for k, v in vp.items() if k != "proof"}
        vp_json = canonical_json(vp_unsigned)
        if not sm2_verify(vp_json.encode(), vp_proof_value[:64], vp_proof_value[64:], vp_pub_x, vp_pub_y):
            errors.append("VP 持有者签名验证失败")
    vc_results = []
    for vc in vp.get("verifiableCredential", []):
        vcr = verify_credential(vc)
        vc_results.append(vcr)
        if not vcr["valid"]: errors.append(f"VC 验证失败: {vcr['errors']}")
        if vcr["issuer"] not in trusted_issuers: errors.append(f"发行方不可信: {vcr['issuer']}")
        # 额外检查VC过期（verify_credential已包含过期检查，此处明确标注）
        expiration = vc.get("expirationDate")
        if expiration:
            try:
                exp_date = datetime.fromisoformat(expiration)
                if datetime.now(timezone.utc) > exp_date:
                    if f"VC已过期，过期时间: {expiration}" not in errors:
                        errors.append(f"VP内含VC已过期: {expiration}")
            except (ValueError, TypeError):
                pass
    disclosed = vp.get("disclosedClaims", {})
    return {
        "valid": len(errors) == 0,
        "holder": vp.get("holder", ""),
        "disclosed": disclosed,
        "disclosure_policy": vp.get("disclosurePolicy", {}),
        "challenge": vp.get("challenge", ""),
        "vc_verification": vc_results,
        "verdict": "权属验证通过 — 数据所有者身份已确认" if len(errors) == 0 else "权属验证失败",
        "errors": errors,
    }

def get_issuer_info():
    return {
        "issuer_did": ISSUER_DID, "issuer_name": ISSUER_NAME,
        "public_key_x": ISSUER_KEYPAIR["public_key_x"],
        "public_key_y": ISSUER_KEYPAIR["public_key_y"],
    }

