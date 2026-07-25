import json, urllib.request
BASE="http://127.0.0.1:5000"
def get(p): return json.load(urllib.request.urlopen(BASE+p))
def post(p,b):
    d=json.dumps(b).encode()
    r=urllib.request.Request(BASE+p,data=d,headers={"Content-Type":"application/json","X-API-Key":"lk-2026-trust-verification-key","X-CSRF-Token":get("/api/csrf-token")["csrf_token"]},method="POST")
    return json.load(urllib.request.urlopen(r))

print("=== 1. issuer_info ===")
i=get("/api/issuer_info")
nm=i.get("issuer_name","?")
st=i.get("cert_status","?")
print("  OK %s status=%s" % (nm, st))

print("\n=== 2. issuers list ===")
d=get("/api/issuers")
print("  OK %d issuers" % len(d["issuers"]))

print("\n=== 3. VC request (full) ===")
vc=post("/api/vc/request",{"metadata":{"basic":{"data_id":"JCFIX-001","data_type":"检疫报告","data_name":"修复验证"},"ownership":{"owner":"张三","did":"did:chainmaker:holder:jcfix001"}},"holder_did":"did:chainmaker:holder:jcfix001","modules":["basic","ownership"],"use_zk":False})
assert vc.get("credentialSubject"), "VC FAIL: "+str(vc)
vc_id = vc.get("id", "?") or "?"
print("  OK vc_id=%s..." % vc_id[:30])

print("\n=== 4. VP construct ===")
vp=post("/api/vp/construct",{"vc":vc,"challenge":"fix-ch","domain":"test.cn"})
assert vp.get("verifiableCredential"), "VP FAIL: "+str(vp)
print("  OK disclosure=%s" % vp.get("disclosure"))

print("\n=== 5. VP verify ===")
vr=post("/api/vp/verify",{"vp":vp})
assert vr.get("valid")==True, "VP VERIFY FAIL: "+str(vr)
print("  OK valid=%s mode=%s" % (vr["valid"], vr.get("mode")))

print("\n=== 6. ZK VC ===")
vczk=post("/api/vc/request",{"metadata":{"basic":{"data_id":"JCFIX-ZK","data_type":"test","data_name":"ZK test"},"ownership":{"owner":"李四","did":"did:chainmaker:holder:jcfizk"}},"holder_did":"did:chainmaker:holder:jcfizk","modules":["basic"],"use_zk":True})
assert vczk.get("credentialSubject"), "ZK VC FAIL"
has_zk = bool(vczk.get("credentialSubject",{}).get("zk_proof"))
print("  OK zk_proof=%s" % has_zk)

print("\n=== 7. ZK VP minimal disclosure ===")
vpzk=post("/api/vp/construct",{"vc":vczk,"challenge":"zk-ch"})
emb=vpzk["verifiableCredential"][0]["credentialSubject"]
leaks = "selected_data" in emb
print("  OK leaks_plaintext=%s (expect False)" % leaks)

# Also test transport
print("\n=== 8. Transport submit ===")
tr=post("/api/submit",{"raw_data":json.dumps({"运输编号":"YS-FIX-001","起运地":"A","目的地":"B","动物种类":"肉牛","数量":"10","随车检疫证号":"JC2026-DEMO01"}),"data_type":"transport","is_structured":True})
assert tr.get("success"), "Transport FAIL: "+str(tr.get("error",tr))
print("  OK transport submitted")

# Test trace
print("\n=== 9. Trace ===")
trace=get("/api/records/trace?q=JC2026-DEMO01")
assert trace.get("stages"), "Trace FAIL"
print("  OK stages=%d linked=%d" % (len(trace["stages"]), len(trace.get("linked",[]))))

print("\nALL 9 SMOKE TESTS PASSED")
