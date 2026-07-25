#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""外部商业 CA 信任锚联邦 - 测试（独立临时 ca_store，绝不污染生产信任锚）

运行环境：VM ~/trust_verification（venv 含 flask/core 依赖）
运行方式：./venv/bin/python3 test_external_ca.py

覆盖：
  1) 内部签发者 VC 基线：valid + issuer_status=valid      （对照组，确保内部 CA 正常）
  2) 克隆为外部签发者 VC（外方密钥重签，承诺数学不变）：注册前 issuer_status=unknown（不可信）
  3) E2E POST /api/external-cas 登记外部商业 CA           （200，写入临时信任锚）
  4) E2E GET  /api/external-cas 含该 CA 且 member 正确
  5) 注册后：外部 VC 变成 issuer_status=external 且 issuer_external_ca=名称（整体 valid）
  6) E2E POST .../disable 停用                            （200）
  7) 停用后：外部 VC 重新 issuer_status=unknown（不可信）
  8) 内部签发者不受外部 CA 任何变更影响（无回归，仍 valid）
  9) E2E POST .../enable 重新启用 → 外部 VC 恢复 external 可信
"""
import os, sys, json, tempfile, copy, hashlib

REPO = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, REPO)

import app as appmod
from app import app as flask_app
import core.issuer_ca as ica
import core.vc_manager as vcmod
import core.sm2_sign as sm2

# ---- 隔离信任锚：重定向 ca_store 单例到临时文件（生产 ca_store.json 完全不动）----
_tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
TMP_STORE = _tmp.name
_tmp.close()
ica.STORE_PATH = TMP_STORE
new_store = ica.CAStore()        # 从种子启动，写入临时文件
ica.ca_store = new_store
vcmod.ca_store = new_store
appmod.ca_store = new_store

KEY = "lk-2026-trust-verification-key"
passed = failed = 0
def log(ok, name, extra=""):
    global passed, failed
    if ok: passed += 1; print("  PASS  " + name + (("  " + extra) if extra else ""))
    else:   failed += 1; print("  FAIL  " + name + (("  " + extra) if extra else ""))

# ---- 样本 ----
HOLDER = "did:trust:livestock:holder:sheep_2026_0881"
META = {
    "basic": {"data_id": "QUAR-2026-0881", "data_type": "检疫报告",
              "data_name": "某牧场生猪检疫报告", "version": "1.0"},
    "ownership": {"owner": "张三是牧场主", "org_id": "ORG-1024",
                  "did": HOLDER, "license": "XK-2026-7788"},
    "content": {"file_size": 204800, "file_type": "pdf",
                "description": "2026年春季生猪检疫合格证明",
                "tags": ["生猪", "合格", "春季"]},
}
MODULES = ["basic", "ownership", "content"]
INT_DID = "did:trust:livestock:issuer:livestock_authority_001"
EXT_DID = "did:trust:livestock:issuer:external_partner_alpha"
EXT_NAME = "合作方商业CA-Alpha"

print("== 外部商业 CA 信任锚联邦 测试 ==")

# 1) 内部签发者 VC（基线）
int_vc = vcmod.request_credential(META, HOLDER, issuer_did=INT_DID, modules=MODULES, use_zk=False)
r_int = vcmod.verify_credential(int_vc)
log(r_int["valid"] and r_int["issuer_status"] == "valid" and r_int["issuer_trusted"],
    "内部签发者 VC 基线验证通过(valid/trusted)", ("status=%s" % r_int["issuer_status"]))

# 2) 克隆为外部签发者 VC，并用外方密钥重签（承诺数学不变）
ext_kp = sm2.generate_keypair()
ext_priv = ext_kp["private_key"]; ext_pub_x = ext_kp["public_key_x"]; ext_pub_y = ext_kp["public_key_y"]
ext_vc = copy.deepcopy(int_vc)
ext_vc["issuer"] = {"id": EXT_DID, "name": "外部商业伙伴Alpha检疫站"}
ext_vc["id"] = "vc:ext-" + hashlib.sha256((HOLDER + "ext" + ext_vc["issuanceDate"]).encode()).hexdigest()[:16]
ext_vc["proof"]["issuerPublicKey"] = {"x": ext_pub_x, "y": ext_pub_y}
ext_vc["proof"]["proofValue"] = sm2.sign_string(vcmod._signable_json(ext_vc), ext_priv)["signature"]

# 3) 注册外部 CA 之前：外部 VC 不可信
r_pre = vcmod.verify_credential(ext_vc)
log((not r_pre["issuer_trusted"]) and r_pre["issuer_status"] == "unknown",
    "注册外部CA前：外部签发者 VC 不可信(unknown)", ("status=%s" % r_pre["issuer_status"]))

# 4) E2E：HTTP 登记外部 CA
client = flask_app.test_client()
r = client.get("/api/csrf-token", headers={"X-API-Key": KEY})
token = (r.get_json() or {}).get("csrf_token", "")
r = client.post("/api/external-cas",
    headers={"X-API-Key": KEY, "X-CSRF-Token": token},
    json={"name": EXT_NAME, "root_public_key_x": ext_pub_x, "root_public_key_y": ext_pub_y,
          "members": [EXT_DID], "note": "测试用外部商业 CA 信任锚"})
body = r.get_json() or {}
ca_id = (body.get("external_ca") or {}).get("id")
log(r.status_code == 200 and body.get("success") is True and bool(ca_id),
    "E2E POST /api/external-cas 成功(200)", ("code=%s id=%s" % (r.status_code, ca_id)))

# 5) E2E：列表应包含该外部 CA 且其 member 含 EXT_DID
r = client.get("/api/external-cas", headers={"X-API-Key": KEY})
lst = (r.get_json() or {}).get("external_cas", [])
log(any(c.get("name") == EXT_NAME and EXT_DID in (c.get("members") or []) for c in lst),
    "E2E GET /api/external-cas 含注册外部CA且 member 正确", ("count=%d" % len(lst)))

# 6) 注册后：外部 VC 变成 external 可信
r_post = vcmod.verify_credential(ext_vc)
log(r_post["issuer_trusted"] and r_post["issuer_status"] == "external"
    and r_post.get("issuer_external_ca") == EXT_NAME,
    "注册外部CA后：外部 VC 变成 external 可信",
    ("status=%s ext_ca=%s" % (r_post["issuer_status"], r_post.get("issuer_external_ca"))))
log(r_post["valid"], "外部 VC 整体 valid=True（签名+承诺+信任锚均通过）")

# 7) E2E：停用外部 CA
r = client.post("/api/external-cas/%s/disable" % ca_id,
    headers={"X-API-Key": KEY, "X-CSRF-Token": token})
log(r.status_code == 200 and (r.get_json() or {}).get("success") is True,
    "E2E POST .../disable 成功(200)", ("code=%s" % r.status_code))

# 8) 停用后：外部 VC 重新不可信
r_off = vcmod.verify_credential(ext_vc)
log((not r_off["issuer_trusted"]) and r_off["issuer_status"] == "unknown",
    "停用外部CA后：外部 VC 重新不可信(unknown)", ("status=%s" % r_off["issuer_status"]))

# 9) 内部签发者不受外部 CA 变更影响（无回归）
r_int2 = vcmod.verify_credential(int_vc)
log(r_int2["valid"] and r_int2["issuer_status"] == "valid",
    "内部签发者不受外部CA变更影响(仍 valid)", ("status=%s" % r_int2["issuer_status"]))

# 10) E2E：重新启用外部 CA 后恢复可信
r = client.post("/api/external-cas/%s/enable" % ca_id,
    headers={"X-API-Key": KEY, "X-CSRF-Token": token})
r_on = vcmod.verify_credential(ext_vc)
log(r_on["issuer_trusted"] and r_on["issuer_status"] == "external",
    "重新启用外部CA后：外部 VC 恢复 external 可信")

# 清理临时信任锚
try: os.remove(TMP_STORE)
except Exception: pass

print("\n结果: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
