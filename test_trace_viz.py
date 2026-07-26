#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""业务状态机可视化（模块⑤）后端测试：每个阶段须携带 region，且被前端地图坐标覆盖。

独立临时 DB，不污染生产数据。运行：./venv/bin/python3 test_trace_viz.py
"""
import os, sys, tempfile, sqlite3, json
import app as appmod
from app import app as flask_app

_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
TMP_DB = _tmp.name
_tmp.close()
appmod.DB_PATH = TMP_DB

_SCHEMA = '''CREATE TABLE IF NOT EXISTS commitments(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  data_did TEXT UNIQUE, data_type TEXT, raw_data TEXT, algorithm TEXT DEFAULT 'SM3',
  fingerprint TEXT, commitment TEXT, randomness TEXT, owner_did TEXT, owner_key TEXT,
  chain_tx_id TEXT, block_height INTEGER, metadata TEXT, vc_id TEXT,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)'''
with sqlite3.connect(TMP_DB) as c:
    c.execute(_SCHEMA); c.commit()

# 前端地图 REGION_COORD 覆盖的区域集合（与 current_vm_index.html 保持一致）
KNOWN_REGIONS = {"华北", "东北", "西南", "华东", "华南", "全国"}

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

print("== 模块⑤ 业务可视化：阶段区域维度 ==")

# 完整链路（无 party_binding -> 用阶段默认区域）
for did, dtype, res, ts in [
    ("TVIZ1-Q", "quarantine", "合格", "2026-07-25T10:00:00+00:00"),
    ("TVIZ1-T", "transaction", "合格", "2026-07-25T11:00:00+00:00"),
    ("TVIZ1-P", "transport",  "合格", "2026-07-25T12:00:00+00:00"),
    ("TVIZ1-S", "slaughter",  "合格", "2026-07-25T13:00:00+00:00"),
]:
    insert(did, dtype, res, ts)
r = trace("TVIZ1")
stages = r.get("stages", [])
log(len(stages) > 0, "链路返回阶段列表")
log(all(s.get("region") in KNOWN_REGIONS for s in stages),
    "全部阶段 region 落在地图覆盖集合内",
    ("regions=" + ",".join(sorted(set(s.get("region","?") for s in stages)))))

# 默认区域映射正确性
def reg(key):
    st = next((s for s in stages if s["key"] == key), None)
    return st.get("region") if st else None
log(reg("cert") == "华北", "cert 阶段默认区域=华北", ("got=" + str(reg("cert"))))
log(reg("trade") == "华东", "trade 阶段默认区域=华东", ("got=" + str(reg("trade"))))
log(reg("trans") == "西南", "trans 阶段默认区域=西南", ("got=" + str(reg("trans"))))
log(reg("slaughter") == "华南", "slaughter 阶段默认区域=华南", ("got=" + str(reg("slaughter"))))

# party_binding.region 覆盖默认
insert("TVIZ2-Q", "quarantine", "合格", "2026-07-25T10:00:00+00:00",
       {"_party_binding": {"region": "东北", "registered": True, "name": "X", "code": "Y"}})
insert("TVIZ2-T", "transaction", "合格", "2026-07-25T11:00:00+00:00")
insert("TVIZ2-P", "transport",  "合格", "2026-07-25T12:00:00+00:00")
insert("TVIZ2-S", "slaughter",  "合格", "2026-07-25T13:00:00+00:00")
r2 = trace("TVIZ2")
st2 = next((s for s in r2.get("stages", []) if s["key"] == "cert"), None)
log(st2 and st2.get("region") == "东北", "party_binding.region 覆盖默认（东北）",
    ("got=" + str(st2.get("region") if st2 else None)))

# 前端坐标完整性：若后续新增区域未加入 REGION_COORD，这里会暴露
log(all(s.get("region") in KNOWN_REGIONS for s in r2.get("stages", [])),
    "TVIZ2 全部阶段 region 亦被地图覆盖")

print("\n结果：%d 通过 / %d 失败" % (passed, failed))
sys.exit(1 if failed else 0)
