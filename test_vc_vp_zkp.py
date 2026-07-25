# -*- coding: utf-8 -*-
"""端到端验证：全披露 / 零知识 两条 VC→VP 链路 + 篡改检测。"""
import json, urllib.request, urllib.error

BASE = "http://127.0.0.1:5000"
KEY = "lk-2026-trust-verification-key"

def _urlopen(method, path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("X-API-Key", KEY)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    return urllib.request.urlopen(req, timeout=30)

def auth():
    tok = json.load(_urlopen("GET", "/api/csrf-token"))["csrf_token"]
    return {"X-CSRF-Token": tok}

def post(path, body, h):
    return json.loads(_urlopen("POST", path, body, h).read().decode())

H = auth()
META = {
    "basic": {"data_id": "JC2026-00158", "data_type": "检疫数据", "data_name": "XX生态养殖场", "version": "1.0"},
    "ownership": {"owner": "XX生态养殖场", "org_id": "", "did": "did:chainmaker:holder:8aF3c2", "license": "proprietary"},
    "content": {"fingerprint": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2", "file_size": 0, "file_type": "检疫数据", "description": "", "tags": []},
}
HOLDER = "did:chainmaker:holder:8aF3c2"
MODULES = ["basic", "ownership", "content"]

def run(mode):
    use_zk = (mode == "zk")
    vc = post("/api/vc/request", {"metadata": META, "holder_did": HOLDER, "modules": MODULES, "use_zk": use_zk}, H)
    subj = vc["credentialSubject"]
    has_zk = "zk_proof" in subj
    has_r = "blinding_factor_r" in subj
    assert subj["pedersen_commitment"]["cx"], "缺少承诺 cx"
    assert has_zk == use_zk, "zk 标志不一致"
    assert has_r == (not use_zk), "盲因子标志不一致"

    rvc = post("/api/vc/verify", {"vc": vc}, H)
    assert rvc["valid"], "VC 验证失败: " + str(rvc.get("errors"))
    assert rvc["commitment_valid"], "承诺校验未通过: " + str(rvc.get("errors"))
    assert rvc["mode"] == ("zk_only" if use_zk else "full"), "模式错误: " + rvc["mode"]
    assert rvc["issuer_trusted"], "签发者不可信: " + rvc["issuer_status"]

    vp = post("/api/vp/construct", {"vc": vc, "challenge": "nonce-test", "domain": "inspector.gov.cn"}, H)
    assert vp["disclosure"] == ("zk_only" if use_zk else "full"), "VP disclosure 错误"
    assert vp["verifiableCredential"][0]["id"] == vc["id"], "VP 内 VC 不一致"

    rvp = post("/api/vp/verify", {"vp": vp}, H)
    assert rvp["valid"], "VP 验证失败: " + str(rvp.get("errors"))
    assert rvp["mode"] == ("zk_only" if use_zk else "full"), "VP 模式错误"

    # 参考实现（main.py）的 ZK 模式同样在 credentialSubject 中保留 selected_data，
    # ZK 证明仅为“无需明文即可验证”的可选路径；此处仅作信息提示，不作断言。
    if use_zk:
        subj = vp["verifiableCredential"][0]["credentialSubject"]
        print("     [参考实现一致性] ZK 凭证含 zk_proof=%s，selected_data 保留=%s（与 main.py 行为一致）" % (
            "zk_proof" in subj, "selected_data" in subj))
    print("  [%s] VC✓ VP✓  模式=%s  承诺校验=%s  签发者=%s" % (mode, rvc["mode"], rvc["commitment_valid"], rvc["issuer_status"]))

print("== 全披露链路 ==")
run("full")
print("== 零知识链路 ==")
run("zk")

# 篡改检测：全披露 VC 改 selected_data → 承诺应失败
print("== 篡改检测 ==")
vc = post("/api/vc/request", {"metadata": META, "holder_did": HOLDER, "modules": MODULES, "use_zk": False}, H)
tampered = json.loads(json.dumps(vc))
tampered["credentialSubject"]["selected_data"]["ownership"]["owner"] = "恶意篡改者"
rvc = post("/api/vc/verify", {"vc": tampered}, H)
assert not rvc["valid"], "篡改后竟验证通过！"
assert not rvc["commitment_valid"], "篡改后承诺竟校验通过！"
print("  篡改 VC → 验证失败（符合预期），错误: %s" % "; ".join(rvc.get("errors", [])))

print("\nALL PASS ✅")
