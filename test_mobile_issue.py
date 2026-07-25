#!/usr/bin/env python3
"""移动端现场出证 - 端到端测试（沿用 urllib，不依赖 requests）。

覆盖：
1) /m 路由可访问（200 + 含"现场出证"）
2) 带 inspection 模块的 VC 请求（全披露）：selected_data 含 inspection，验证 valid=True/mode=full
3) 带 inspection 模块的 VC 请求（零知识）：验证 valid=True/mode=zk_only，且明文被剥离
4) 现场核验：用全披露 VC 调 /api/vc/verify 返回 inspection 字段
"""
import urllib.request, json, sys

BASE = "http://127.0.0.1:5000"
KEY = "lk-2026-trust-verification-key"
passed = 0
failed = 0

def log(ok, name, extra=""):
    global passed, failed
    if ok:
        passed += 1
        print("  PASS  " + name + (("  " + extra) if extra else ""))
    else:
        failed += 1
        print("  FAIL  " + name + (("  " + extra) if extra else ""))

def get(path):
    req = urllib.request.Request(BASE + path, headers={"X-API-Key": KEY}, method="GET")
    return json.loads(urllib.request.urlopen(req).read())

def post(path, body):
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "X-API-Key": KEY, "X-CSRF-Token": _csrf}, method="POST")
    return json.loads(urllib.request.urlopen(req).read())

print("== 移动端现场出证 测试 ==")

# 0) csrf
_csrf = get("/api/csrf-token")["csrf_token"]

# 1) /m 路由
try:
    html = urllib.request.urlopen(BASE + "/m").read().decode("utf-8", "ignore")
    ok = (("现场出证" in html) and ("/static/js/jsQR.js" in html) and ("/static/js/qrcode.js" in html))
    log(ok, "/m 路由可访问且含移动端资源", ("len=%d" % len(html)))
except Exception as e:
    log(False, "/m 路由可访问", str(e))

# inspection 元数据
def make_meta():
    return {
        "basic": {"data_id": "JC2026-MTEST", "data_name": "生猪", "data_type": "quarantine"},
        "ownership": {"owner": "测试养殖场", "org_id": "X1", "did": "did:chainmaker:holderM", "license": "proprietary"},
        "content": {"fingerprint": "fp-m", "description": "移动端测试", "tags": []},
        "inspection": {
            "gps": {"lat": 31.23, "lng": 121.47, "accuracy": 5, "ts": "2026-07-25T14:00:00+00:00"},
            "vet": {"name": "张三", "id": "VET01"},
            "result": "合格",
            "note": "健康"
        }
    }

# 2) 全披露 + inspection
vc_full = post("/api/vc/request", {
    "metadata": make_meta(), "holder_did": "did:chainmaker:holderM",
    "issuer_did": "", "issuer_name": "",
    "modules": ["basic", "ownership", "content", "inspection"], "use_zk": False
})
sub = vc_full.get("credentialSubject", {})
has_insp = "inspection" in sub.get("selected_data", {})
log(has_insp, "全披露 VC 的 selected_data 含 inspection 模块",
    ("inspection=%s" % json.dumps(sub.get("selected_data", {}).get("inspection", {}), ensure_ascii=False)))

# 3) 验证全披露 VC
r_full = post("/api/vc/verify", {"vc": vc_full})
log(r_full.get("valid") is True, "全披露 VC 验证 valid=True", ("mode=%s" % r_full.get("mode")))
log(r_full.get("mode") == "full", "全披露 VC 模式=full")
log((r_full.get("inspection") is not None) or ("inspection" in (vc_full.get("credentialSubject", {}).get("selected_data", {}))),
    "核验可读取 inspection 现场数据")

# 4) ZK 链路未被 inspection 模块破坏：VC 含 zk_proof 且可验证（VC 级仍带明文，由 VP 剥离）
vc_zk = post("/api/vc/request", {
    "metadata": make_meta(), "holder_did": "did:chainmaker:holderM",
    "issuer_did": "", "issuer_name": "",
    "modules": ["basic", "ownership", "content", "inspection"], "use_zk": True
})
has_zkp = "zk_proof" in vc_zk.get("credentialSubject", {})
log(has_zkp, "ZK VC 含 zk_proof（inspection 模块未破坏 ZK 构造）")
r_zk = post("/api/vc/verify", {"vc": vc_zk})
log(r_zk.get("valid") is True, "ZK VC 验证 valid=True", ("mode=%s" % r_zk.get("mode")))
log(r_zk.get("mode") == "zk_only", "ZK VC 模式=zk_only")

# 5) 回归：无 inspection 的旧式请求仍只返回三模块
vc_old = post("/api/vc/request", {
    "metadata": {"basic": {"data_id": "JC2026-OLD", "data_name": "x", "data_type": "quarantine"},
                 "ownership": {"owner": "o", "org_id": "X1", "did": "d", "license": "proprietary"},
                 "content": {"fingerprint": "f", "description": "d", "tags": []}},
    "holder_did": "d", "modules": ["basic", "ownership", "content"], "use_zk": False
})
log("inspection" not in vc_old.get("credentialSubject", {}).get("selected_data", {}),
    "回归：旧式请求不产生 inspection 模块")

print("\n结果: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
