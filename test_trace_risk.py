#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""业务状态机风险预警 - 后端逻辑测试（独立临时 DB，不污染生产数据）。

运行环境：VM ~/trust_verification（venv 含 flask/core 依赖）
运行方式：./venv/bin/python3 test_trace_risk.py

覆盖：
  S1 完整链路（全 合格 + 合规间隔）      -> risks 为空，complete=True
  S2 缺失运输环节                         -> high 风险含"运输配送"，complete=False
  S3 超 SLA（cert->trade 间隔 30h>24h）   -> medium 风险含"超时"，cert 阶段 timeout=True
  S4 检疫未通过（不合格）                -> high 风险含"未通过"，quarantine_ok=False，dispose 阶段 required
  回归：对线上服务 /api/records/trace 仍返回 summary.risks（字段存在，向后兼容）
"""
import os, sys, tempfile, sqlite3, json, urllib.request

# ---- 1) 导入应用（独立进程，仅 import-time 的 CREATE TABLE IF NOT EXISTS 作用真实库，无数据更改）----
import app as appmod
from app import app as flask_app

# ---- 2) 隔离 DB：指向临时文件 ----
_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
TMP_DB = _tmp.name
_tmp.close()
appmod.DB_PATH = TMP_DB

# ---- 3) 在临时库建表（与 app.py schema 一致）----
_SCHEMA = '''CREATE TABLE IF NOT EXISTS commitments(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  data_did TEXT UNIQUE, data_type TEXT, raw_data TEXT, algorithm TEXT DEFAULT 'SM3',
  fingerprint TEXT, commitment TEXT, randomness TEXT, owner_did TEXT, owner_key TEXT,
  chain_tx_id TEXT, block_height INTEGER, metadata TEXT, vc_id TEXT,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)'''
with sqlite3.connect(TMP_DB) as c:
    c.execute(_SCHEMA)
    c.commit()

passed = failed = 0
def log(ok, name, extra=""):
    global passed, failed
    if ok: passed += 1; print("  PASS  " + name + (("  " + extra) if extra else ""))
    else:   failed += 1; print("  FAIL  " + name + (("  " + extra) if extra else ""))

def insert(did, dtype, result, ts, metadata_extra=None):
    meta = {"检疫结果": result}
    if metadata_extra: meta.update(metadata_extra)
    with sqlite3.connect(TMP_DB) as c:
        c.execute("INSERT OR REPLACE INTO commitments(data_did, data_type, metadata, timestamp) VALUES (?,?,?,?)",
                  (did, dtype, json.dumps(meta, ensure_ascii=False), ts))
        c.commit()

def trace(q):
    client = flask_app.test_client()
    return json.loads(client.get("/api/records/trace?q=" + q).data)

print("== 业务状态机风险预警 测试 ==")

# ---- S1 完整链路 ----
for did, dtype, res, ts in [
    ("TRISK1-Q", "quarantine", "合格", "2026-07-25T10:00:00+00:00"),
    ("TRISK1-T", "transaction", "合格", "2026-07-25T11:00:00+00:00"),
    ("TRISK1-P", "transport",  "合格", "2026-07-25T12:00:00+00:00"),
    ("TRISK1-S", "slaughter",  "合格", "2026-07-25T13:00:00+00:00"),
]:
    insert(did, dtype, res, ts)
r1 = trace("TRISK1")
log(r1.get("summary", {}).get("risks", "MISSING") == [], "S1 完整链路无风险",
    ("risks=%s" % json.dumps(r1.get("summary", {}).get("risks", []), ensure_ascii=False)))
log(r1.get("summary", {}).get("complete") is True, "S1 链路完整 complete=True")

# ---- S2 缺失运输 ----
for did, dtype, res, ts in [
    ("TRISK2-Q", "quarantine", "合格", "2026-07-25T10:00:00+00:00"),
    ("TRISK2-T", "transaction", "合格", "2026-07-25T11:00:00+00:00"),
    ("TRISK2-S", "slaughter",  "合格", "2026-07-25T12:00:00+00:00"),
]:
    insert(did, dtype, res, ts)
# 注意：不插入 transport
r2 = trace("TRISK2")
risks2 = r2.get("summary", {}).get("risks", [])
log(any(rk.get("level") == "high" and "运输" in rk.get("msg", "") for rk in risks2),
    "S2 缺失运输触发 high 风险", ("risks=%s" % json.dumps(risks2, ensure_ascii=False)))
log(r2.get("summary", {}).get("complete") is False, "S2 链路不完整 complete=False")

# ---- S3 超 SLA（cert->trade 30h > 24h）----
for did, dtype, res, ts in [
    ("TRISK3-Q", "quarantine", "合格", "2026-07-25T10:00:00+00:00"),
    ("TRISK3-T", "transaction", "合格", "2026-07-26T16:00:00+00:00"),  # +30h
    ("TRISK3-P", "transport",  "合格", "2026-07-26T17:00:00+00:00"),
    ("TRISK3-S", "slaughter",  "合格", "2026-07-26T18:00:00+00:00"),
]:
    insert(did, dtype, res, ts)
r3 = trace("TRISK3")
risks3 = r3.get("summary", {}).get("risks", [])
log(any(rk.get("level") == "medium" and "超时" in rk.get("msg", "") for rk in risks3),
    "S3 超 SLA 触发 medium 风险", ("risks=%s" % json.dumps(risks3, ensure_ascii=False)))
cert_stage = next((s for s in r3.get("stages", []) if s.get("key") == "cert"), {})
log(cert_stage.get("timeout") is True, "S3 cert 阶段 timeout=True")

# ---- S4 检疫未通过 ----
insert("TRISK4-Q", "quarantine", "不合格", "2026-07-25T10:00:00+00:00")
r4 = trace("TRISK4")
risks4 = r4.get("summary", {}).get("risks", [])
log(any(rk.get("level") == "high" and "未通过" in rk.get("msg", "") for rk in risks4),
    "S4 检疫未通过触发 high 风险", ("risks=%s" % json.dumps(risks4, ensure_ascii=False)))
log(r4.get("summary", {}).get("quarantine_ok") is False, "S4 quarantine_ok=False")
dispose = next((s for s in r4.get("stages", []) if s.get("key") == "dispose"), {})
log(dispose.get("status") == "required", "S4 出现无害化处理阶段(required)")

# ---- 回归：线上服务仍返回 summary.risks（字段存在、向后兼容）----
try:
    req = urllib.request.Request("http://127.0.0.1:5000/api/records/trace?q=JC2026-DEMO01",
                                 headers={"X-API-Key": "lk-2026-trust-verification-key"})
    live = json.loads(urllib.request.urlopen(req, timeout=8).read())
    has_risks = isinstance((live.get("summary") or {}).get("risks"), list)
    log(has_risks, "回归：线上 /api/records/trace 返回 summary.risks 字段",
        ("stages=%d" % len(live.get("stages", []))))
except Exception as e:
    log(False, "回归：线上 trace 调用", str(e))

# ---- 清理临时库 ----
try: os.remove(TMP_DB)
except Exception: pass

print("\n结果: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
