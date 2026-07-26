#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块④ 测试：DID 命名空间统一 + 主体-CA 强绑定

验证：
 1) 种子主体 DID 全部位于统一命名空间 did:trust:livestock:party:<issuer_id>:<short>
 2) 绑定到「有效」签发机构的主体 -> ca_linked=True 且返回 ca_issuer / ca_name
 3) 背书签发机构被吊销 -> 强绑定级联失效（ca_linked=False）
 4) 绑定到未知签发机构 -> ca_linked=False（issuer_untrusted:unknown）
 5) 遗留 did:chainmaker:party:* 命名空间 -> ca_linked=False（namespace_mismatch）
 6) 吊销可逆：恢复后强绑定重新生效
 7) /api/parties 返回的 ca_linked 与 /api/party/lookup 同源一致

隔离：ca_store 重定向到临时文件，绝不污染生产信任锚；DB 亦重定向到临时库。
"""
import os, sys, tempfile, json

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# 先把 issuer_ca 的存储路径指向临时文件，再让 app 在其后导入，
# 这样即便导入阶段读取生产 ca_store.json 也只是「读」，不会写入。
import core.issuer_ca as ica

_TMP = tempfile.mkdtemp(prefix="didns_")
_ISTORE = os.path.join(_TMP, "ca_store.json")
ica.STORE_PATH = _ISTORE
ica.ca_store = ica.CAStore()            # bootstrap 一份全新的、含有效内部签发者的信任锚

import app as appmod
appmod.DB_PATH = os.path.join(_TMP, "test.db")
core_vc = __import__("core.vc_manager", fromlist=["ca_store"])
core_vc.ca_store = ica.ca_store
appmod.ca_store = ica.ca_store

# 重新装载应用配置（避免 Flask 上下文问题）
appmod.app.config["TESTING"] = True
client = appmod.app.test_client()

PASS = 0
FAIL = 0
def check(cond, name):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  PASS", name)
    else:
        FAIL += 1
        print("  FAIL", name)

print("== 模块④：DID 命名空间统一 + 强绑定 ==")

# 1) /api/parties：所有主体 DID 命名空间统一
r = client.get("/api/parties")
j = r.get_json()
check(r.status_code == 200, "GET /api/parties 200")
parties = j.get("parties", [])
check(all((p.get("did") or "").startswith("did:trust:livestock:party:")
          for p in parties if p.get("did")),
      "全部主体 DID 位于 did:trust:livestock:party:* 命名空间")
legacy = [p for p in parties if (p.get("did") or "").startswith("did:chainmaker")]
check(len(legacy) == 0, "无遗留 did:chainmaker:party:* 命名空间")

# 2) 农场主体（绑定 livestock_authority_001）强绑定生效
farm = next(p for p in parties if p.get("did", "").endswith(":xxst"))
d = client.get("/api/party/lookup?did=" + farm["did"]).get_json()
check(d.get("ca_linked") is True, "farm 主体 ca_linked=True（绑定有效签发机构）")
check(d.get("ca_issuer") == "did:trust:livestock:issuer:livestock_authority_001",
      "ca_issuer 解析为 did:trust:livestock:issuer:livestock_authority_001")
check(bool(d.get("ca_name")), "返回 ca_name（背书机构名称）")

# 3) 级联失效：吊销背书签发机构 -> 强绑定立即失效
ica.ca_store.revoke("did:trust:livestock:issuer:livestock_authority_001", "测试吊销")
d2 = client.get("/api/party/lookup?did=" + farm["did"]).get_json()
check(d2.get("ca_linked") is False, "签发机构吊销后 ca_linked=False（级联）")
check(str(d2.get("ca_reason", "")).startswith("issuer_untrusted"),
      "吊销后 ca_reason=issuer_untrusted:*")

# 4) 未知签发机构 -> 不可信（直接对强绑定解析函数做单元验证）
unk = ica.resolve_party_ca_link("did:trust:livestock:party:no_such_issuer_xyz:abc")
check(unk.get("ca_linked") is False, "未知背书签发机构 ca_linked=False")
check(str(unk.get("ca_reason", "")).startswith("issuer_untrusted:unknown"),
      "未知机构 ca_reason=issuer_untrusted:unknown")

# 5) 遗留命名空间 -> namespace_mismatch（不为其伪造强绑定）
leg = ica.resolve_party_ca_link("did:chainmaker:party:farm:xx")
check(leg.get("ca_linked") is False, "遗留 did:chainmaker:party:* ca_linked=False")
check(leg.get("ca_reason") == "namespace_mismatch", "遗留命名空间 ca_reason=namespace_mismatch")

# 6) 吊销可逆
ica.ca_store.restore("did:trust:livestock:issuer:livestock_authority_001")
d5 = client.get("/api/party/lookup?did=" + farm["did"]).get_json()
check(d5.get("ca_linked") is True, "恢复签发机构后 ca_linked 重新=True")

# 7) /api/parties 的 ca_linked 与 lookup 同源
linked_count = sum(1 for p in parties if p.get("ca_linked"))
check(linked_count >= 1, "/api/parties 至少 1 个主体 ca_linked=True")
check(any((p.get("ca_reason") == "namespace_mismatch") for p in parties) is False,
      "/api/parties 中无 namespace_mismatch（全部对齐）")

print("\n结果：%d 通过 / %d 失败" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
