"""
NLP 对照抽取模块 —— 任务1「元数据抽取」的 NLP/DL 对照路径

与 core.metadata_extractor 的「规则解析」（基于 key:value 结构切分）不同，
本模块走**自然语言处理**路线：从**自由文本**中通过统计分词 + 领域词典 NER
抽取实体，不依赖结构化 key:value 格式。用于对齐申报书任务1中
"元数据抽取（自然语言处理或深度学习方法）"的措辞。

实现策略（务实、VM 无 GPU、零强依赖）：
  - 主路径：纯标准库正则 + 领域词典 NER（NLP-lite），保证无外部依赖也能跑、绝不崩。
  - 增强路径：若运行环境装了 jieba，则启用 jieba.posseg 词性标注做 NER 增强
    （nr=人名 / nt=机构名 / t=时间），method 标注为 jieba 增强。
  - 预留接口：transformers 预训练 NER（GPU 环境启用），通过 _try_transformers() 钩子，
    当前默认不启用，避免重依赖拖垮受限环境。

输出 schema 与 core.metadata_extractor.extract_metadata 完全一致，
使 submit / verify 可在 rule 与 nlp 两条路径间切换而不破坏指纹一致性。
"""
import re

# ---- 领域词典（畜牧业检疫业务） ----
ANIMAL_DICT = [
    "猪", "牛", "羊", "鸡", "鸭", "鹅", "兔", "马", "驴", "骡",
    "生猪", "肉牛", "肉羊", "仔猪", "种猪", "奶牛", "蛋鸡", "肉鸡", "蛋鸭", "肉鸭",
    "长白猪", "大白猪", "杜洛克", "大约克", "荷斯坦牛", "西门塔尔牛", "波尔山羊", "小尾寒羊",
]
ANIMAL_DICT_SORTED = sorted(ANIMAL_DICT, key=len, reverse=True)

ORG_SUFFIXES = [
    "集团公司", "集团", "养殖有限公司", "养殖公司", "养殖合作社", "养殖基地", "养殖场",
    "养殖农场", "屠宰有限公司", "屠宰厂", "屠宰场", "食品有限公司", "食品公司",
    "物流有限公司", "运输公司", "畜牧兽医站", "防疫站", "动物卫生监督所",
    "农业农村局", "畜牧局", "农业发展服务中心", "农牧科技有限公司", "实业有限公司",
]
ORG_KEYWORDS = ["公司", "集团", "合作社", "养殖场", "基地", "屠宰", "食品", "物流", "运输",
                "兽医站", "防疫站", "监督所", "农业", "畜牧", "服务中心", "科技", "实业"]
PERSON_SUFFIX = ["员", "医", "站长", "主任", "经理", "科长"]
RESULT_PASS = ["合格", "PASS", "通过", "健康", "阴性"]
RESULT_FAIL = ["不合格", "FAIL", "未通过", "患病", "阳性", "违规"]

# 字段模板（与 core.metadata_extractor.TEMPLATES 对齐，保证 schema 一致）
TEMPLATES = {
    "quarantine": {
        "fields": ["检疫编号", "检疫日期", "检疫机构", "检疫结果", "动物种类", "数量",
                   "养殖场名称", "养殖场地址", "检疫员", "有效期至"],
        "type": "检疫记录",
    },
    "transaction": {
        "fields": ["交易编号", "交易日期", "卖方", "买方", "动物种类", "数量",
                   "单价", "总价", "交易地点", "付款方式"],
        "type": "交易记录",
    },
    "transport": {
        "fields": ["运输编号", "起运日期", "到达日期", "起运地", "目的地", "运输工具",
                   "车牌号", "司机", "动物种类", "数量", "运输企业"],
        "type": "运输记录",
    },
    "slaughter": {
        "fields": ["屠宰编号", "屠宰日期", "屠宰企业", "动物种类", "数量", "检疫合格证号",
                   "屠宰方式", "官方兽医", "产品去向", "批次号"],
        "type": "屠宰记录",
    },
}

# 正则
RE_DATE = re.compile(r'(\d{4})[-年./](\d{1,2})[-月./](\d{1,2})日?')
RE_DATE_SLASH = re.compile(r'(\d{4})/(\d{1,2})/(\d{1,2})')
RE_COUNT = re.compile(r'(\d+(?:\.\d+)?)\s*(头|只|羽|尾|匹|kg|KG|公斤|千克|吨|头份)')
RE_CERT = re.compile(r'(JC\d{4}-[A-Z0-9]+|[\u4e00-\u9fa5]?检字?\[?\d{4}\]?\d+)')
RE_PLATE = re.compile(r'([京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领][A-Z][A-Z0-9]{4,5}[A-Z0-9挂学警港澳]{1})')
RE_ADDR = re.compile(r'([一-龥]{2,}(?:省|市|区|县|镇|乡|村|路|街道))')
RE_PRICE = re.compile(r'(?:单价|总价|金额|价格)[是为:：]?\s*([¥￥]?\d+(?:\.\d+)?)\s*(元|万元)?')

_JIEBA = None
_JIEBA_POSSEG = None
_jieba_ok = None  # None=未探测; True=已加载; False=不可用


def _ensure_jieba():
    """可选增强：尝试加载 jieba，失败则降级到标准库。用独立哨兵避免 False 歧义。"""
    global _JIEBA, _JIEBA_POSSEG, _jieba_ok
    if _jieba_ok is not None:
        return _jieba_ok
    try:
        import jieba  # type: ignore
        import jieba.posseg as posseg  # type: ignore
        for w in ANIMAL_DICT + ORG_SUFFIXES:
            jieba.add_word(w)
        _JIEBA = jieba
        _JIEBA_POSSEG = posseg
        _jieba_ok = True
        return True
    except Exception:
        _JIEBA = None
        _JIEBA_POSSEG = None
        _jieba_ok = False
        return False


def _try_transformers():
    """预留：GPU 环境下可启用预训练 NER。当前默认不启用（避免重依赖）。"""
    return None


def _norm_date(m):
    """把多种日期格式归一化为 YYYY-MM-DD。"""
    try:
        y, mo, d = m.group(1), m.group(2), m.group(3)
        return f"{int(y):04d}-{int(mo):02d}-{int(d):02d}"
    except Exception:
        return None


def _extract_entities(text):
    """从自由文本抽取实体集合，返回结构化实体 dict。"""
    entities = {
        "dates": [], "counts": [], "cert_nos": [], "plates": [],
        "animals": [], "orgs": [], "persons": [], "results": [],
        "prices": [], "addresses": [],
    }
    # 日期
    for m in RE_DATE.finditer(text):
        d = _norm_date(m)
        if d and d not in entities["dates"]:
            entities["dates"].append(d)
    for m in RE_DATE_SLASH.finditer(text):
        d = _norm_date(m)
        if d and d not in entities["dates"]:
            entities["dates"].append(d)
    # 数量
    for m in RE_COUNT.finditer(text):
        entities["counts"].append(f"{m.group(1)}{m.group(2)}")
    # 证号
    for m in RE_CERT.finditer(text):
        entities["cert_nos"].append(m.group(1))
    # 车牌
    for m in RE_PLATE.finditer(text):
        entities["plates"].append(m.group(1))
    # 动物
    for a in ANIMAL_DICT_SORTED:
        if a in text and a not in entities["animals"]:
            entities["animals"].append(a)
    # 地址
    for m in RE_ADDR.finditer(text):
        if m.group(1) not in entities["addresses"]:
            entities["addresses"].append(m.group(1))
    # 价格
    for m in RE_PRICE.finditer(text):
        entities["prices"].append(m.group(1) + (m.group(2) or ""))
    # 结果
    for w in RESULT_PASS:
        if w in text and "合格" not in entities["results"]:
            entities["results"].append("合格")
            break
    if not entities["results"]:
        for w in RESULT_FAIL:
            if w in text:
                entities["results"].append("不合格")
                break
    # 机构 / 人名抽取：jieba 增强优先，标准库降级仅作 jieba 不可用时的兜底（避免污染）
    if _ensure_jieba():
        for w in _JIEBA_POSSEG.cut(text):
            if w.flag in ("nt", "org") and len(w.word) >= 2:
                if w.word not in entities["orgs"]:
                    entities["orgs"].append(w.word)
            elif w.flag == "nr" and len(w.word) >= 2:
                if w.word not in entities["persons"]:
                    entities["persons"].append(w.word)
    else:
        # 标准库降级 NER（jieba 不可用）：扩展分隔符，避免机构名吞掉前置行政区划/日期
        _SEP = "，。、\n 省市区县镇乡村路街道号组屯"
        for suf in ORG_SUFFIXES:
            idx = 0
            while True:
                i = text.find(suf, idx)
                if i < 0:
                    break
                start = max(0, max((text.rfind(s, 0, i) for s in _SEP), default=-1) + 1)
                org = text[start:i + len(suf)].strip("，。、\n ")
                if org and org not in entities["orgs"] and 2 <= len(org) <= 30:
                    entities["orgs"].append(org)
                idx = i + len(suf)
        RE_PERSON = re.compile(r'(?:检疫员|官方兽医|司机|负责人|经办人|记录员|兽医|填报人|承运人)[是为:：]?\s*([一-龥]{2,3})')
        for m in RE_PERSON.finditer(text):
            p = m.group(1)
            if p not in entities["persons"]:
                entities["persons"].append(p)
    return entities


def _map_to_fields(entities, data_type):
    """把抽取到的实体映射到该 data_type 的字段模板。"""
    tpl = TEMPLATES.get(data_type, {"fields": [], "type": data_type})
    metadata = {"data_type": tpl["type"]}
    f = tpl["fields"]
    e = entities

    def pick(field, vals, idx=0):
        if field in f and vals:
            metadata[field] = vals[min(idx, len(vals) - 1)]

    # 通用字段
    pick("动物种类", e["animals"])
    pick("数量", e["counts"])
    pick("检疫编号", e["cert_nos"])
    pick("检疫合格证号", e["cert_nos"])
    pick("车牌号", e["plates"])
    pick("检疫结果", e["results"])
    # 日期类：第一个作主日期，第二个（如有）作有效期/到达
    if e["dates"]:
        pick("检疫日期", e["dates"], 0)
        pick("起运日期", e["dates"], 0)
        pick("交易日期", e["dates"], 0)
        pick("屠宰日期", e["dates"], 0)
        if len(e["dates"]) > 1:
            pick("有效期至", e["dates"], 1)
            pick("到达日期", e["dates"], 1)
    # 机构类
    if e["orgs"]:
        pick("检疫机构", e["orgs"], 0)
        pick("养殖场名称", e["orgs"], 0)
        pick("屠宰企业", e["orgs"], 0)
        pick("运输企业", e["orgs"], 0)
        pick("卖方", e["orgs"], 0)
        pick("买方", e["orgs"], 1 if len(e["orgs"]) > 1 else 0)
        pick("交易地点", e["orgs"], 0)
    # 人名类
    if e["persons"]:
        pick("检疫员", e["persons"], 0)
        pick("官方兽医", e["persons"], 0)
        pick("司机", e["persons"], 0)
    # 地址
    if e["addresses"]:
        pick("养殖场地址", e["addresses"], 0)
        pick("起运地", e["addresses"], 0)
        pick("目的地", e["addresses"], 0)
        pick("产品去向", e["addresses"], 0)
    # 价格
    if e["prices"]:
        pick("单价", e["prices"], 0)
        pick("总价", e["prices"], 0)
    return metadata


def extract_metadata_nlp(raw_data: str, data_type: str) -> dict:
    """NLP 对照抽取入口，输出与规则解析同 schema 的 dict。"""
    text = (raw_data or "").strip()
    entities = _extract_entities(text)
    metadata = _map_to_fields(entities, data_type)
    tpl = TEMPLATES.get(data_type, {"fields": []})
    matched = sum(1 for fld in tpl["fields"] if fld in metadata)
    total = len(tpl["fields"])
    confidence = round(matched / total, 4) if total else 0.5
    method = "NLP统计抽取(jieba+HMM+词典NER)" if _ensure_jieba() else "NLP-lite(标准库正则+词典NER)"
    return {
        "metadata": metadata,
        "confidence": confidence,
        "data_type": tpl["type"],
        "method": method,
        "matched_fields": matched,
        "total_fields": total,
        "need_review": confidence < 0.7,
        "_nlp_entities": {k: v for k, v in entities.items() if v},
    }
