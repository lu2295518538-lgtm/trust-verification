"""
ETL 字段抽取 + NLP/NER 实体抽取
"""
import re

TEMPLATES = {
    "quarantine": {
        "fields": ["检疫编号","检疫日期","检疫机构","检疫结果","动物种类","数量","养殖场名称","养殖场地址","检疫员","有效期至"],
        "type": "检疫记录",
    },
    "transaction": {
        "fields": ["交易编号","交易日期","卖方","买方","动物种类","数量","单价","总价","交易地点","付款方式"],
        "type": "交易记录",
    },
    "transport": {
        "fields": ["运输编号","起运日期","到达日期","起运地","目的地","运输工具","车牌号","司机","动物种类","数量","运输企业"],
        "type": "运输记录",
    },
    "slaughter": {
        "fields": ["屠宰编号","屠宰日期","屠宰企业","动物种类","数量","检疫合格证号","屠宰方式","官方兽医","产品去向","批次号"],
        "type": "屠宰记录",
    },
}

def extract_metadata(raw_data: str, data_type: str, is_structured: bool = True) -> dict:
    import json as _json
    template = TEMPLATES.get(data_type, {"fields": [], "type": data_type})
    metadata = {"data_type": template["type"]}
    stripped = raw_data.strip()

    # ── 检测 JSON 格式输入（运输/交易等前端常以 JSON 提交）──
    _json_obj = None
    if stripped.startswith('{') or stripped.startswith('['):
        try:
            _json_obj = _json.loads(stripped)
            if isinstance(_json_obj, dict):
                metadata.update(_json_obj)
            elif isinstance(_json_obj, list) and _json_obj:
                metadata.update(_json_obj[0] if isinstance(_json_obj[0], dict) else {})
        except (ValueError, TypeError):
            _json_obj = None

    # ── 回退：按行解析 key:value ──
    if not _json_obj:
        lines = [l.strip() for l in stripped.split('\n') if l.strip()]
        for line in lines:
            for sep in [': ', '：', ':']:
                if sep in line:
                    parts = line.split(sep, 1)
                    if len(parts) == 2:
                        metadata[parts[0].strip()] = parts[1].strip()
                    break

    matched = sum(1 for f in template["fields"] if f in metadata)
    confidence = matched / len(template["fields"]) if template["fields"] else 0.5
    return {
        "metadata": metadata, "confidence": round(confidence, 4),
        "data_type": template["type"], "method": "ETL" if is_structured else "NER",
        "matched_fields": matched, "total_fields": len(template["fields"]),
        "need_review": confidence < 0.85,
    }
