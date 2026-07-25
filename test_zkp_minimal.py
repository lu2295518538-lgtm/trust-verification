# -*- coding: utf-8 -*-
"""
端到端验证：VC/VP 构造 + 零知识真正最小披露 + 篡改检测
运行：~/trust_verification/venv/bin/python3 test_zkp_minimal.py
"""
import json
from core.vc_manager import (
    request_credential, verify_credential,
    construct_presentation, verify_presentation,
)

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


def _show(tag, vc):
    subj = vc.get("credentialSubject", {})
    print("    %s: 含 selected_data=%s 含 zk_proof=%s 含 blinding_factor_r=%s"
          % (tag, "selected_data" in subj, "zk_proof" in subj,
             "blinding_factor_r" in subj))


print("== 全披露链路 ==")
vc_full = request_credential(META, HOLDER, modules=MODULES, use_zk=False)
rvc = verify_credential(vc_full)
vp_full = construct_presentation(vc_full, modules=MODULES, challenge="ch-full", domain="demo")
rvp = verify_presentation(vp_full)
assert rvc["valid"] and rvc["commitment_valid"], "全披露 VC 校验失败: " + str(rvc["errors"])
assert rvp["valid"], "全披露 VP 校验失败: " + str(rvp["errors"])
print("  [full] VC✓ VP✓  模式=%s  承诺校验=%s" % (rvc["mode"], rvc["commitment_valid"]))
_show("全披露 VC(持证人主凭证)", vc_full)

print("\n== 零知识链路 ==")
vc_zk = request_credential(META, HOLDER, modules=MODULES, use_zk=True)
rvc_zk = verify_credential(vc_zk)
vp_zk = construct_presentation(vc_zk, modules=MODULES, challenge="ch-zk", domain="demo")
rvp_zk = verify_presentation(vp_zk)
assert rvc_zk["valid"] and rvc_zk["zk_verified"], "零知识 VC 校验失败: " + str(rvc_zk["errors"])
assert rvp_zk["valid"], "零知识 VP 校验失败: " + str(rvp_zk["errors"])
print("  [zk] VC✓ VP✓  模式=%s  承诺校验=%s  ZK验证=%s"
      % (rvc_zk["mode"], rvc_zk["commitment_valid"], rvc_zk["zk_verified"]))
_show("零知识 VC(持证人主凭证, 仍含明文备出示)", vc_zk)

# 关键：零知识 VP 内嵌的 VC 不得含明文 selected_data —— 真正最小披露
embedded = vp_zk["verifiableCredential"][0]
assert "selected_data" not in embedded.get("credentialSubject", {}), \
    "零知识 VP 仍携带明文 selected_data，最小披露未落实！"
print("  [最小披露] 零知识 VP 已剔除明文 selected_data ✓（验证方仅见承诺+ZKP）")
print("     VP 披露模式=%s  holder(DID)=%s  验证结论=%s"
      % (vp_zk["disclosure"], vp_zk["holder"], rvp_zk["verdict"]))

print("\n== 零知识真落地一致性 ==")
# 全披露 VP 仍应含明文（供验证方核对承诺）；零知识 VP 不应含明文。
assert "selected_data" in vp_full["verifiableCredential"][0].get("credentialSubject", {}), \
    "全披露 VP 不应缺失明文 selected_data"
print("  [对照] 全披露 VP 含明文(selected_data) ✓  |  零知识 VP 无明文(selected_data) ✓")

print("\n== 篡改检测（全披露）==")
tampered = json.loads(json.dumps(vc_full))
tampered["credentialSubject"]["selected_data"]["ownership"]["owner"] = "恶意篡改者"
rt = verify_credential(tampered)
assert not rt["valid"], "篡改后竟仍判定有效！"
assert not rt["commitment_valid"], "篡改后承诺竟校验通过！"
print("  [篡改] VC 验证=%s  承诺校验=%s  错误=%s"
      % (rt["valid"], rt["commitment_valid"], rt["errors"]))

print("\nALL PASS ✅  零知识真正最小披露已落地，全链路与篡改检测均正确。")
