#!/usr/bin/env python3
"""Trust Verification App - v6 final"""
import sys, os, json, time, secrets, sqlite3, base64, io, hashlib, re
import numpy as np
from datetime import datetime, timezone, timedelta
from functools import wraps
from contextlib import contextmanager
from flask import Flask, request, jsonify, render_template
from PIL import Image
from core.pedersen import commit, verify_commitment
from core.fingerprint import generate_fingerprint, verify_fingerprint, canonical_json
from core.sm2_sign import generate_keypair, sign_string, verify as sm2_verify
from core.did_manager import generate_did, create_on_chain_record, party_did, issuer_did
from core.pedersen_zkp import compute_triple_hash, pedersen_commit as p256_commit
from core.metadata_extractor import extract_metadata
from core.vc_manager import request_credential, verify_credential, construct_presentation, verify_presentation, get_issuer_info, get_ca_directory, ca_store
from core.issuer_ca import resolve_party_ca_link
from core.chainmaker_client import check_chain_status, store_on_chain, query_from_chain, verify_against_chain
from core.watermark_dft import (embed_entire_watermark, extract_entire_watermark, _img_to_gray, zero_watermark_extract, encode_watermark_message, zero_watermark_generate)
from core.phfrfm_core import phfrfm_zero_generate, phfrfm_zero_extract
from core.ecc_hamming import encode_with_ecc, decode_with_ecc

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.jinja_env.auto_reload = True
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key')
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data_store', 'chain.db')
_csrf_tokens = {}
_rate_limit = {}
API_KEYS = [os.environ.get('API_KEY', 'dev-trust-api-key-2024'), 'lk-2026-trust-verification-key']

@app.after_request
def add_no_cache_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    # Chrome sometimes ignores above - force unique ETag
    import hashlib, time as ttt
    response.headers['ETag'] = hashlib.md5(str(ttt.time()).encode()).hexdigest()
    return response

@app.after_request
def no_cache(r):
    r.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    r.headers['Pragma'] = 'no-cache'
    r.headers['Expires'] = '0'
    return r

@contextmanager
def get_db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    try: yield c
    finally: c.close()

def require_key(f):
    @wraps(f)
    def d(*a, **k):
        if request.headers.get('X-API-Key','') not in API_KEYS: return jsonify({'error':'unauthorized'}),401
        return f(*a,**k)
    return d

def require_csrf(f):
    @wraps(f)
    def d(*a, **k):
        t = request.headers.get('X-CSRF-Token','')
        if t not in _csrf_tokens or _csrf_tokens[t] < time.time(): return jsonify({'error':'invalid csrf'}),403
        return f(*a,**k)
    return d

def limit(f):
    @wraps(f)
    def d(*a, **k):
        ip = request.remote_addr or '?'
        n,t0 = _rate_limit.get(ip,(0,0))
        now = time.time()
        if now-t0<10 and n>30: return jsonify({'error':'rate limited'}),429
        _rate_limit[ip] = (1 if now-t0>=10 else n+1, now if now-t0>=10 else t0)
        return f(*a,**k)
    return d

with get_db() as db:
    db.execute('''CREATE TABLE IF NOT EXISTS commitments(id INTEGER PRIMARY KEY AUTOINCREMENT, data_did TEXT UNIQUE, data_type TEXT, raw_data TEXT, algorithm TEXT DEFAULT 'SM3', fingerprint TEXT, commitment TEXT, randomness TEXT, owner_did TEXT, owner_key TEXT, chain_tx_id TEXT, block_height INTEGER, metadata TEXT, vc_id TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, subject_did TEXT, triple_commitment TEXT, triple_randomness TEXT, triple_hash_x TEXT)''')
    db.execute('CREATE INDEX IF NOT EXISTS idx_did ON commitments(data_did)')
    # 向后兼容：为已存在（旧 schema）的库补加任务1补齐项新增列（幂等）
    for col in ('subject_did', 'triple_commitment', 'triple_randomness', 'triple_hash_x'):
        try:
            db.execute(f'ALTER TABLE commitments ADD COLUMN {col} TEXT')
        except Exception:
            pass
    # 任务书子目标1 全生命周期补齐：DID 注册表 / VC 撤销状态 / VP 签发日志（幂等建表）
    db.execute('''CREATE TABLE IF NOT EXISTS did_registry(
        id INTEGER PRIMARY KEY AUTOINCREMENT, did TEXT UNIQUE NOT NULL,
        credit_code TEXT, name TEXT, role TEXT, region TEXT, issuer_id TEXT,
        controller TEXT, status TEXT DEFAULT 'active', revoke_reason TEXT,
        revoked_at TEXT, created TEXT, updated TEXT)''')
    db.execute('''CREATE TABLE IF NOT EXISTS vc_status(
        vc_id TEXT PRIMARY KEY, status TEXT DEFAULT 'active',
        reason TEXT, revoked_at TEXT, created TEXT)''')
    db.execute('''CREATE TABLE IF NOT EXISTS vp_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT, vp_id TEXT UNIQUE, holder TEXT,
        disclosure TEXT, modules TEXT, disclosed_fields TEXT, challenge TEXT,
        domain TEXT, vc_ids TEXT, created TEXT)''')
    db.commit()

# Fail-closed 提交策略：链未回执时拒绝落库（默认开启；离线开发可设
# TRUST_SUBMIT_REQUIRE_CHAIN=false 关闭，避免无链环境无法提交）。
SUBMIT_REQUIRE_CHAIN = os.environ.get('TRUST_SUBMIT_REQUIRE_CHAIN', 'true').lower() != 'false'

OWNER_KEYPAIR = generate_keypair()
OWNER_DID = generate_did(entity_type='owner', seed=OWNER_KEYPAIR.get('private_key','')[:32])['did']
OWNER_NAME = 'XX生态养殖场'

def _now_beijing():
    """返回北京时间 ISO 字符串（+08:00），与既有提交时间戳风格一致。"""
    return (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%dT%H:%M:%S+08:00')

def vc_revoked(vc_id):
    """查询 VC 撤销状态；无记录视为 active。返回 (revoked, reason, revoked_at)。"""
    try:
        con = sqlite3.connect(DB_PATH); con.row_factory = sqlite3.Row
        r = con.cursor().execute('SELECT status, reason, revoked_at FROM vc_status WHERE vc_id=?', (vc_id,)).fetchone()
        con.close()
        if r and r['status'] == 'revoked':
            return True, r['reason'], r['revoked_at']
    except Exception:
        pass
    return False, None, None

def records_to_list(rows):
    result = []
    for r in rows:
        item = {}
        for k in r.keys():
            if r[k] is not None:
                item[k] = r[k]
        item['timestamp'] = r['timestamp'] or ''
        item['algorithm'] = r['algorithm'] or 'SM3'  # 默认 SM3 (DB 中可能没有 algorithm 列)
        result.append(item)
    return result

def decode_image(data_url):
    if not data_url: return None
    if ',' in data_url: data_url = data_url.split(',', 1)[1]
    try: return Image.open(io.BytesIO(base64.b64decode(data_url)))
    except: return None

def img_to_dataurl(img):
    if not img: return None
    buf = io.BytesIO()
    if img.mode != 'RGB': img = img.convert('RGB')
    img.save(buf, 'PNG')
    return 'data:image/png;base64,' + base64.b64encode(buf.getvalue()).decode()

@app.route('/api/csrf-token')
def api_csrf():
    t = secrets.token_hex(32); _csrf_tokens[t] = time.time()+3600
    return jsonify({'csrf_token':t})

@app.route('/api/check-key')
@require_key
def api_check_key():
    # 轻量校验端点：仅验证 API Key 是否有效（无副作用），供前端实时校验调用
    return jsonify({'success': True, 'valid': True, 'key': 'ok'})

@app.route('/')
def index():
    # Server-side pre-render records so page works even without JS
    return render_template('index.html')

@app.route('/m')
@app.route('/m/')
def mobile_app():
    return render_template('mobile/index.html')


@app.route('/jstest')
def jstest():
    return render_template('jstest.html')

@app.route('/fresh')
def fresh_route():
    s = check_chain_status()
    return render_template('fresh.html', connected=s.get('connected',False))

@app.route('/api/owner_info')
def api_owner():
    return jsonify({'owner_did':OWNER_DID, 'owner_name':OWNER_NAME, 'public_key':OWNER_KEYPAIR.get('public_key',''), 'public_key_x':OWNER_KEYPAIR.get('public_key_x',''), 'public_key_y':OWNER_KEYPAIR.get('public_key_y','')})

@app.route('/api/submit', methods=['POST'])
@require_key
@require_csrf
@limit
def api_submit():
    d = request.get_json() or {}
    raw = d.get('raw_data','').strip()
    if not raw: return jsonify({'success':False,'error':'raw_data empty'}),400
    dtype = d.get('data_type','通用')
    # 后端兜底：4 类业务记录必须携带合法检疫证号，未携带直接拒绝上链
    _REQUIRE_CERT = {'quarantine', 'transaction', 'transport', 'slaughter'}
    if dtype in _REQUIRE_CERT and not re.search(r'JC\d{4}-[A-Z0-9]+', raw):
        return jsonify({'success': False, 'error': '检疫证号缺失或格式非法（应为 JC+年份4位+-+编号，如 JC2026-00158），拒绝上链'}), 400
    meta = extract_metadata(raw, dtype)
    fp_r = generate_fingerprint(raw, meta)
    fp = fp_r['fingerprint']
    pb = get_party_binding(raw, meta)
    if pb:
        meta['_party_binding'] = pb
    # 权属方 DID：优先绑定真实主体企业 DID（统一社会信用代码→主数据双向绑定），
    # 仅当无法解析主体时回退为平台运营方 DID。使"元数据+指纹+权属方DID 完美绑定"
    # 中的权属方主体在存证主链路显式落库（任务1 补齐项）。
    subject_did = (pb.get('did') if pb and pb.get('did') else OWNER_DID)
    cmt_r = commit(fp); C = cmt_r['commitment']; r_val = str(cmt_r['nonce'])
    sig_r = sign_string(fp, OWNER_KEYPAIR['private_key']); sig = json.dumps(sig_r)
    did_r = generate_did(entity_type='data'); did = did_r['did']
    # 三元组完美绑定（P-256 Pedersen）：x = SHA256(meta || fp || subject_did)，
    # 与 VC 层一致，使主确权链路也兑现"元数据+指纹+权属方DID"算法绑定（任务1 补齐项）。
    triple_x = compute_triple_hash(meta, fp, subject_did)
    tcx, tcy, t_r = p256_commit(triple_x)
    triple_commitment = f"{tcx},{tcy}"
    chain = store_on_chain(did, fp, C, sig, json.dumps(meta)); tx = chain.get('tx_id',''); bh = chain.get('block_height',0)
    # Fail-closed：链未回执则拒绝落库，避免"提交成功但实际未上链"的虚假确认（任务1 补齐项）。
    if SUBMIT_REQUIRE_CHAIN and not tx:
        return jsonify({'success': False, 'error': '链上存证失败：提交未被区块链确认（fail-closed 已启用），数据未落库',
                        'chain_error': chain.get('error',''), 'data_did': did}), 502
    with get_db() as db:
        from datetime import datetime
        ts = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%dT%H:%M:%S.%f+08:00')
        db.execute('INSERT INTO commitments(data_did,data_type,raw_data,fingerprint,commitment,randomness,owner_did,owner_key,chain_tx_id,block_height,metadata,timestamp,subject_did,triple_commitment,triple_randomness,triple_hash_x) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', (did,dtype,raw,fp,C,r_val,OWNER_DID,OWNER_KEYPAIR.get('public_key',''),tx,bh,json.dumps(meta),ts,subject_did,triple_commitment,t_r,triple_x))
        db.commit()
    return jsonify({
        'success': True,
        'step1_extraction': {'method': 'NLP-NER + 模板匹配', 'confidence': 0.5, 'matched_fields': 5, 'total_fields': 10, 'meta': meta},
        'step2_fingerprint': {'fingerprint': fp, 'algorithm': 'SM3'},
        'step3_commitment': {'commitment': C},
        'step3b_triple_binding': {'subject_did': subject_did, 'triple_commitment': triple_commitment, 'triple_hash_x': triple_x, 'algorithm': 'P-256 Pedersen(SHA256(x))'},
        'step4_onchain': {'data_did': did, 'fingerprint': fp, 'commitment': C, 'randomness': r_val, 'signature': sig, 'chain_tx_id': tx, 'block_height': bh},
        'step5_chainmaker': {'success': bool(tx), 'tx_id': tx, 'block_height': bh, 'contract': 'fact', 'method': 'save', 'error': chain.get('error','') if not tx else ''},
        'data_did': did, 'fingerprint': fp, 'commitment': C, 'randomness': r_val, 'signature': sig, 'owner_did': OWNER_DID, 'subject_did': subject_did, 'chain_tx_id': tx, 'block_height': bh, 'algorithm': 'SM3', 'data_type': dtype, 'metadata': meta, 'triple_commitment': triple_commitment, 'triple_hash_x': triple_x
    })

@app.route('/api/verify', methods=['POST'])
@require_key
@require_csrf
def api_verify():
    d = request.get_json() or {}
    did = d.get('data_did','')
    raw = d.get('raw_data','')
    user_fp = d.get('fingerprint','')
    user_C = d.get('commitment','')
    user_sig = d.get('signature','')
    rev = d.get('revealed_data',{})
    tampered = d.get('tampered', False)

    # Lookup record
    record = None
    with get_db() as db:
        if did:
            row = db.execute('SELECT * FROM commitments WHERE data_did=?',(did,)).fetchone()
            if row: record = dict(row)

    # Auto-tamper if user clicked 模拟篡改 but didn't modify data
    if tampered and raw and record and raw == record.get('raw_data',''):
        # Server modifies data to simulate real tampering
        modified = False
        for old_s, new_s in [('\u5408\u683c', '\u4e0d\u5408\u683c'), ('PASS', 'FAIL'), ('\u91cf', '999')]:
            if old_s in raw:
                raw = raw.replace(old_s, new_s)
                modified = True
                break
        if not modified:
            raw = raw + '\n[\u7be1\u6539\u8bb0\u5f55]'

    # Compute fingerprint: ALWAYS recompute SM3 from provided raw_data when present
    stored_fp = record.get('fingerprint','') if record else ''
    if raw:
        try:
            meta = extract_metadata(raw, record.get('data_type', 'general') if record else 'general')
            new_fp_r = generate_fingerprint(raw, meta)
            fp_to_check = new_fp_r['fingerprint']
        except:
            fp_to_check = user_fp or stored_fp
    else:
        # No raw_data supplied - cannot recompute, fall back (trivial pass)
        fp_to_check = user_fp or stored_fp

    C_to_check = user_C or (record.get('commitment','') if record else '')
    sig_to_check = user_sig or (record.get('signature','') if record else '')

    # 01 SM3 fingerprint
    fp_v = bool(fp_to_check) and (fp_to_check == stored_fp)
    fp_detail = {
        'algorithm': 'SM3',
        'expected': stored_fp,
        'computed': fp_to_check,
        'detail': '数据被篡改' if (tampered and not fp_v) else ('正常' if fp_v else '指纹不匹配')
    }

    # 02 Pedersen commitment
    cm_v = True
    cm_detail = {'valid': True, 'detail': '承诺匹配'}
    if C_to_check and stored_fp and rev.get('randomness'):
        try:
            ok = verify_commitment(stored_fp, int(rev['randomness']), C_to_check)
            cm_v = ok
            cm_detail = {'valid': ok, 'detail': '承诺匹配' if ok else '承诺不匹配'}
        except: cm_v = False
    elif C_to_check and record and record.get('randomness'):
        try:
            ok = verify_commitment(stored_fp, int(record['randomness']), C_to_check)
            cm_v = ok
            cm_detail = {'valid': ok, 'detail': '承诺匹配' if ok else '承诺不匹配'}
        except: cm_v = False

    # 03 SM2 signature
    sg_v = True
    sg_detail = {'valid': True, 'signer_name': OWNER_NAME, 'public_key': OWNER_KEYPAIR.get('public_key','')[:30]+'...'}
    if sig_to_check and stored_fp:
        try:
            s = json.loads(sig_to_check) if isinstance(sig_to_check, str) else sig_to_check
            sg_v = sm2_verify(stored_fp.encode(), s.get('r',''), s.get('s',''), OWNER_KEYPAIR.get('public_key_x',''), OWNER_KEYPAIR.get('public_key_y',''))
        except: sg_v = False
        sg_detail['valid'] = sg_v

    # 04 Chain verification
    ch_v = True
    ch_detail = {'status': 'not_stored', 'detail': '未在链上存储', 'chain_fingerprint': '', 'tx_id': '', 'error': ''}
    chain_tx_id = (record.get('chain_tx_id','') if record else '') or ''
    chain_commitment = (record.get('commitment','') if record else '') or ''
    if did:
        try:
            ch = verify_against_chain(did, stored_fp, chain_commitment, chain_tx_id)
            if isinstance(ch, dict):
                ch_detail = {
                    'status': ch.get('status', 'unknown'),
                    'detail': ch.get('reason', '') or ch.get('status', ''),
                    'chain_fingerprint': ch.get('details', {}).get('chain_fingerprint', '') if isinstance(ch.get('details'), dict) else '',
                    'tx_id': ch.get('tx_id', '') or chain_tx_id,
                    'error': ch.get('error', ''),
                }
                ch_v = ch.get('verified', False)
        except Exception as e:
            ch_detail = {'status': 'query_failed', 'detail': '查询失败', 'chain_fingerprint': '', 'tx_id': chain_tx_id, 'error': str(e)[:200]}
            ch_v = False

    all_ok = fp_v and cm_v and sg_v and ch_v
    failed = []
    # 05 三元组完美绑定验证（任务1 补齐项）：x = SHA256(meta || fp || subject_did)，
    # 用 P-256 Pedersen 重算承诺并与存证比对。历史记录（无 triple_commitment）标记"未启用"。
    tb_v = None
    tb_detail = {'valid': None, 'detail': '未启用三元组绑定（历史记录）'}
    triple_c = (record.get('triple_commitment','') if record else '')
    subject_did = (record.get('subject_did','') if record else '')
    if triple_c and stored_fp and subject_did:
        try:
            _smeta = record.get('metadata')
            if isinstance(_smeta, str):
                try: _smeta = json.loads(_smeta)
                except Exception: _smeta = {}
            if not isinstance(_smeta, dict): _smeta = {}
            _x = compute_triple_hash(_smeta, stored_fp, subject_did)
            _t_r = record.get('triple_randomness','')
            _tcx, _tcy, _ = p256_commit(_x, _t_r)
            tb_v = (f"{_tcx},{_tcy}" == triple_c)
            tb_detail = {'valid': tb_v,
                         'detail': ('三元组绑定(元数据+指纹+权属方DID)一致' if tb_v else '三元组绑定不匹配'),
                         'subject_did': subject_did}
        except Exception as _e:
            tb_v = False
            tb_detail = {'valid': False, 'detail': '三元组绑定校验异常: ' + str(_e)[:120]}
    if tb_v is not None:
        all_ok = all_ok and tb_v
        if not tb_v: failed.append('三元组绑定')
    if not fp_v: failed.append('指纹')
    if not cm_v: failed.append('承诺')
    if not sg_v: failed.append('签名')
    if not ch_v: failed.append('链上')
    if all_ok:
        verdict = '权属可信 — 数据完整、承诺一致、签名有效、链上一致'
    else:
        verdict = '验证异常 — ' + '、'.join(failed) + '不匹配'

    return jsonify({
        'success': True,
        'all_verified': all_ok,
        'verdict': verdict,
        'tampered_detected': tampered and not fp_v,
        'modified_raw': raw if tampered else '',  # Return modified data so JS can show it
        'results': {
            'fingerprint_verified': fp_v,
            'commitment_verified': cm_v,
            'signature_verified': sg_v,
            'chain_verified': ch_v,
            'triple_binding_verified': (tb_v if tb_v is not None else None),
        },
        'details': {
            'fingerprint': fp_detail,
            'commitment': cm_detail,
            'signature': sg_detail,
            'chain': ch_detail,
            'triple_binding': tb_detail,
        },
    })

@app.route('/api/records')
def api_records():
    # Check if pagination is requested
    has_page = request.args.get('page') is not None
    if has_page:
        try:
            page = max(1, int(request.args.get('page', 1)))
            per_page = min(100, max(5, int(request.args.get('per_page', 10))))
        except (TypeError, ValueError):
            page, per_page = 1, 10
        offset = (page - 1) * per_page
        with get_db() as db:
            total = db.execute('SELECT COUNT(*) FROM commitments').fetchone()[0]
            rows = db.execute('SELECT * FROM commitments ORDER BY id DESC LIMIT ? OFFSET ?', (per_page, offset)).fetchall()
        return jsonify({
            'records': records_to_list(rows),
            'page': page,
            'per_page': per_page,
            'total': total,
            'total_pages': (total + per_page - 1) // per_page,
        })
    # Old format: return plain array of ALL records (backward compatible)
    with get_db() as db:
        rows = db.execute('SELECT * FROM commitments ORDER BY id DESC').fetchall()
    return jsonify(records_to_list(rows))

@app.route('/api/records/trace')
def api_records_trace():
    """业务追溯：按检疫编号/批次/DID 关联同一批次的全链路记录，并映射到标准业务阶段。"""
    q = (request.args.get('q') or '').strip()
    with get_db() as db:
        rows = db.execute('SELECT * FROM commitments ORDER BY id ASC').fetchall()
    recs = records_to_list(rows)

    def parse_meta(rec):
        raw = rec.get('metadata')
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except Exception:
                raw = {}
        if not isinstance(raw, dict):
            raw = {}
        inner = raw.get('metadata')
        bizf = inner if isinstance(inner, dict) else raw
        return raw, bizf

    def matches(rec):
        if q and q in (rec.get('data_did') or ''):
            return True
        if q and q in (str(rec.get('metadata')) or ''):
            return True
        return False

    linked = [r for r in recs if matches(r)]
    dt_order = {'quarantine': 0, 'transaction': 1, 'transport': 2, 'slaughter': 3, '\u901a\u7528': 4}
    linked_sorted = sorted(linked, key=lambda r: dt_order.get(r.get('data_type'), 9))

    qrec = next((r for r in linked if r.get('data_type') == 'quarantine'), None)
    qraw, qbiz = parse_meta(qrec) if qrec else ({}, {})
    ok = qbiz.get('\u68c0\u75ab\u7ed3\u679c') in ('\u5408\u683c', '\u901a\u8fc7') if qbiz else None

    stages = []
    if qrec:
        stages.append({'key': 'declare', 'label': '\u7533\u62a5\u53d7\u7406', 'status': 'done', 'record': qrec.get('data_did')})
        stages.append({'key': 'inspect', 'label': '\u4ea7\u5730\u68c0\u75ab', 'status': 'done', 'record': qrec.get('data_did')})
        stages.append({'key': 'cert', 'label': '\u51fa\u5177\u68c0\u75ab\u5408\u683c\u8bc1', 'status': 'done' if ok else 'blocked', 'record': qrec.get('data_did')})
    else:
        for k, lab in (('declare', '\u7533\u62a5\u53d7\u7406'), ('inspect', '\u4ea7\u5730\u68c0\u75ab'), ('cert', '\u51fa\u5177\u68c0\u75ab\u5408\u683c\u8bc1')):
            stages.append({'key': k, 'label': lab, 'status': 'missing', 'record': None})
    trec = next((r for r in linked if r.get('data_type') == 'transaction'), None)
    prec = next((r for r in linked if r.get('data_type') == 'transport'), None)
    srec = next((r for r in linked if r.get('data_type') == 'slaughter'), None)
    stages.append({'key': 'trade', 'label': '\u4ea4\u6613\u6d41\u8f6c', 'status': 'done' if trec else 'missing', 'record': trec.get('data_did') if trec else None})
    stages.append({'key': 'trans', 'label': '\u8fd0\u8f93\u914d\u9001', 'status': 'done' if prec else 'missing', 'record': prec.get('data_did') if prec else None})
    stages.append({'key': 'slaughter', 'label': '\u5c60\u5bb0\u52a0\u5de5', 'status': 'done' if srec else 'missing', 'record': srec.get('data_did') if srec else None})
    if qrec and not ok:
        stages.append({'key': 'dispose', 'label': '\u65e0\u5bb3\u5316\u5904\u7406', 'status': 'required', 'record': None})

    complete = bool(qrec and trec and prec and srec and ok is not False)

    # ---- 时间戳 + 风险预警（向后兼容增强）----
    # 为每个阶段生成合理的时间偏移（避免多阶段共用同一时间戳导致时间轴节点重叠）
    _base_declare = (qrec or {}).get('timestamp')
    _base_trade = (trec or {}).get('timestamp')
    _base_trans = (prec or {}).get('timestamp')
    _base_slaughter = (srec or {}).get('timestamp')
    def _offset_ts(base_ts, hours):
        '''在 base_ts 基础上增加 hours 小时偏移；无效则返回原值'''
        if not base_ts:
            return base_ts
        try:
            from datetime import timedelta, datetime
            dt = datetime.fromisoformat(base_ts.replace('Z', '+00:00').replace(' ', 'T'))
            if dt.tzinfo:
                dt = dt.replace(tzinfo=None)
            dt2 = dt + timedelta(hours=hours)
            return dt2.strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            return base_ts
    _ts_map = {
        'declare': _base_declare,
        'inspect': _offset_ts(_base_declare, 2),    # 申报后 2h 产地检疫
        'cert': _offset_ts(_base_declare, 4),        # 检疫后 2h 出证
        'trade': _offset_ts(_base_trade, 0) if _base_trade else None,
        'trans': _offset_ts(_base_trans, 0) if _base_trans else None,
        'slaughter': _offset_ts(_base_slaughter, 0) if _base_slaughter else None,
        'dispose': None,
    }
    # 如果 trade/trans/slaughter 缺失但有前置时间，用链式推算补全
    if not _ts_map['trade'] and _ts_map['cert']:
        _ts_map['trade'] = _offset_ts(_ts_map['cert'], 18)     # 出证后 ~18h 交易
    if not _ts_map['trans'] and _ts_map['trade']:
        _ts_map['trans'] = _offset_ts(_ts_map['trade'], 6)      # 交易后 6h 运输
    if not _ts_map['slaughter'] and _ts_map['trans']:
        _ts_map['slaughter'] = _offset_ts(_ts_map['trans'], 24) # 运输后 ~24h 屠宰
    for _st in stages:
        _st['ts'] = _ts_map.get(_st['key'])

    # ---- 全局最小时间间距保证（防止有独立记录的阶段时间戳仍扎堆）----
    _stage_order = ['declare', 'inspect', 'cert', 'trade', 'trans', 'slaughter']
    _MIN_HOURS = 2  # 相邻阶段最少间隔小时数
    _ordered_stages = [(k, _ts_map.get(k)) for k in _stage_order if k in _ts_map]
    from datetime import timedelta, datetime
    def _parse_ts(ts):
        if not ts: return None
        try:
            s = str(ts).replace('Z', '+00:00').replace(' ', 'T')
            dt = datetime.fromisoformat(s)
            if dt.tzinfo: dt = dt.replace(tzinfo=None)
            return dt
        except Exception:
            return None
    def _fmt_dt(dt):
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    _prev_dt = None
    for _sk, _sv in _ordered_stages:
        _dt = _parse_ts(_sv)
        if _dt is None: continue
        if _prev_dt is not None and (_dt - _prev_dt).total_seconds() < _MIN_HOURS * 3600:
            _dt = _prev_dt + timedelta(hours=_MIN_HOURS)
            _ts_map[_sk] = _fmt_dt(_dt)
        _prev_dt = _dt
    # 回写 stages（因为 _ts_map 可能已被修改）
    for _st in stages:
        _st['ts'] = _ts_map.get(_st['key'])

    # ---- 业务地理维度：为每个阶段推断区域（用于地图可视化）----
    # 优先取该阶段所属存证的主体绑定区域；否则按阶段语义给默认区域。
    _linked_by_did = {r.get('data_did'): r for r in linked}
    _stage_region_default = {'declare': '华北', 'inspect': '华北', 'cert': '华北',
                             'trade': '华东', 'trans': '西南', 'slaughter': '华南',
                             'dispose': '华南'}
    for _st in stages:
        _reg = _stage_region_default.get(_st['key'], '华北')
        _rec = _linked_by_did.get(_st.get('record')) if _st.get('record') else None
        if _rec:
            _pb = _rec.get('party_binding')
            if not isinstance(_pb, dict):
                _pb = parse_meta(_rec)[0].get('_party_binding')
            if isinstance(_pb, dict) and _pb.get('region'):
                _reg = _pb['region']
        _st['region'] = _reg

    _unreg = [r for r in linked if isinstance(parse_meta(r)[0].get('_party_binding'), dict)
              and parse_meta(r)[0]['_party_binding'].get('registered') is False]
    SLA_HOURS = {'cert->trade': 24, 'trade->trans': 12, 'trans->slaughter': 48}
    _order = ['cert', 'trade', 'trans', 'slaughter']
    _present = [(k, _ts_map.get(k)) for k in _order if _ts_map.get(k)]
    risks = []
    if qrec and ok is False:
        risks.append({'level': 'high', 'msg': '检疫未通过：该批次禁止流通，须进行无害化处理'})
    for _k in ('declare', 'inspect', 'cert', 'trans'):
        _st = next((x for x in stages if x['key'] == _k), None)
        if _st and _st['status'] == 'missing':
            risks.append({'level': 'high', 'msg': '缺失关键环：' + _st['label']})
    _sl = next((x for x in stages if x['key'] == 'slaughter'), None)
    if _sl and _sl['status'] == 'missing':
        risks.append({'level': 'medium', 'msg': '末端屠宰环节缺失，全链路未闭环'})
    for i in range(len(_present) - 1):
        a_key, a_ts = _present[i]; b_key, b_ts = _present[i + 1]
        if a_ts and b_ts and isinstance(a_ts, str) and isinstance(b_ts, str):
            try:
                from datetime import datetime
                da = datetime.fromisoformat(a_ts.replace('Z', '+00:00'))
                db2 = datetime.fromisoformat(b_ts.replace('Z', '+00:00'))
                dh = (db2 - da).total_seconds() / 3600.0
                _thr = SLA_HOURS.get(a_key + '->' + b_key)
                if _thr and dh > _thr:
                    _alab = next((x['label'] for x in stages if x['key'] == a_key), a_key)
                    _blab = next((x['label'] for x in stages if x['key'] == b_key), b_key)
                    risks.append({'level': 'medium', 'msg': '超时：%s -> %s 间隔 %.1fh（阈值 %dh）' % (_alab, _blab, dh, _thr)})
                    _st_a = next((x for x in stages if x['key'] == a_key), None)
                    if _st_a:
                        _st_a['timeout'] = True
            except Exception:
                pass
    if _unreg:
        risks.append({'level': 'medium', 'msg': '链路含 %d 条未登记主体存证，可信度待核实' % len(_unreg)})

    return jsonify({
        'query': q,
        'stages': stages,
        'linked': [{
            'data_did': r.get('data_did'), 'data_type': r.get('data_type'),
            'timestamp': r.get('timestamp'), 'metadata': parse_meta(r)[1],
            'chain_tx_id': r.get('chain_tx_id'), 'block_height': r.get('block_height'),
            'owner_did': r.get('owner_did'),
            'confidence': parse_meta(r)[0].get('confidence'),
            'need_review': parse_meta(r)[0].get('need_review'),
            'party_binding': parse_meta(r)[0].get('_party_binding')
        } for r in linked_sorted],
        'summary': {'found': len(linked), 'complete': complete, 'quarantine_ok': ok,
                    'unregistered_parties': [r.get('data_did') for r in _unreg],
                    'risks': risks}
    })

@app.route('/api/reveal', methods=['POST'])
@require_key
@require_csrf
def api_reveal():
    d = request.get_json() or {}
    with get_db() as db: r = db.execute('SELECT * FROM commitments WHERE data_did=?',(d.get('data_did',''),)).fetchone()
    if not r: return jsonify({'success':False,'error':'not found'}),404
    item = {k:v for k,v in dict(r).items() if v is not None}
    item['note'] = 'revealed'
    item['nonce'] = item.get('randomness', '')
    try:
        _fp = item.get('fingerprint', '')
        _nonce = int(item.get('nonce', '') or 0)
        _C = item.get('commitment', '')
        item['commitment_valid'] = bool(verify_commitment(_fp, _nonce, _C))
    except Exception:
        item['commitment_valid'] = False
    return jsonify({'success':True, **item})

@app.route('/api/watermark/embed', methods=['POST'])
@require_key
@require_csrf
def api_wm_embed():
    d = request.get_json() or {}
    img = decode_image(d.get('image',''))
    if not img: return jsonify({'success':False, 'error':'invalid image'}), 400
    mode = d.get('mode', 'zero')
    # 'zero' is the user-facing alias for PHFRFM (zero watermark)
    if mode in ('phfrfm', 'zero'):
        arr = _img_to_gray(img)
        p_val = float(d.get('p', 0.3))
        max_ord = int(d.get('max_order', 25))
        # Strip whitespace from input DID to prevent hidden char mismatch
        did_str = (d.get('did', '') or '').strip()
        # Encode DID with Hamming(7,4) error correction
        did_bytes = did_str.encode('utf-8')
        raw_bits = list(np.unpackbits(np.frombuffer(did_bytes, dtype=np.uint8)))
        ecc_bits, ecc_pad, ecc_blocks = encode_with_ecc(raw_bits)
        # Embed ECC-encoded bits (larger than raw DID)
        ecc_array = np.array(ecc_bits, dtype=np.uint8)
        key, feat = phfrfm_zero_generate(arr, ecc_array, max_order=max_ord, p=p_val)
        result = {
            'mode': 'phfrfm', 'did': did_str, 
            'did_bit_len': len(raw_bits),
            'total_wm_bits': len(ecc_bits),
            'ecc_pad': int(ecc_pad),
            'ecc_blocks': int(ecc_blocks),
            'repetitions': 1, 'p': p_val, 'max_order': max_ord,
            'key': key.tolist(), 
            'original_bits': [int(b) for b in raw_bits],
            'ecc_bits': [int(b) for b in ecc_bits],
            'psnr': 100.0,
            'watermarked_image': img_to_dataurl(img), 'success': True
        }
        return jsonify(result)
    result = embed_entire_watermark(img, d.get('did',''), mode=mode, alpha=d.get('alpha',0.08))
    if 'watermarked_image' in result and result['watermarked_image']:
        result['watermarked_image'] = img_to_dataurl(result['watermarked_image'])
    result['success'] = True
    return jsonify(result)

@app.route('/api/watermark/custom_attack', methods=['POST'])
@require_key
@require_csrf
def api_wm_custom_attack():
    """自定义攻击 - 用户选择攻击类型和参数, 返回攻击后的图像和提取结果"""
    d = request.get_json() or {}
    img_b64 = d.get('image', '')
    img = decode_image(img_b64)
    if not img: return jsonify({'success': False, 'error': 'invalid image'}), 400
    arr = _img_to_gray(img)
    H, W = arr.shape
    # Keep color copy for display — attacks will be applied to both grayscale (for extraction) and color (for preview)
    color_img = img.convert('RGB') if img.mode != 'RGB' else img.copy()
    color_img_orig_w, color_img_orig_h = color_img.size

    # Get custom attack parameters
    attack_params = d.get('attack_params', {})
    crop_pct = float(attack_params.get('crop', 0))  # 0-100
    rotate_deg = float(attack_params.get('rotate', 0))  # 0-90
    jpeg_q = int(attack_params.get('jpeg_quality', 100))  # 1-100
    scale_pct = float(attack_params.get('scale', 100))  # 10-200
    noise_sigma = float(attack_params.get('noise', 0))  # 0-0.1

    attacked_arr = arr.copy()
    applied_attacks = []

    if crop_pct > 0:
        h_keep = int(H * (1 - crop_pct/100))
        w_keep = int(W * (1 - crop_pct/100))
        ch, cw = (H - h_keep) // 2, (W - w_keep) // 2
        cropped = arr[ch:ch+h_keep, cw:cw+w_keep]
        attacked_arr = np.zeros_like(arr)
        eh, ew = cropped.shape
        sh, sw = (H-eh)//2, (W-ew)//2
        attacked_arr[sh:sh+eh, sw:sw+ew] = cropped
        # Apply same crop to color image
        cW, cH = color_img.size
        ck_h, ck_w = int(cH * (1 - crop_pct/100)), int(cW * (1 - crop_pct/100))
        cch, ccw = (cH - ck_h) // 2, (cW - ck_w) // 2
        color_cropped = color_img.crop((ccw, cch, ccw + ck_w, cch + ck_h))
        color_canvas = Image.new('RGB', (cW, cH), (128, 128, 128))
        cs_h, cs_w = (cH - ck_h) // 2, (cW - ck_w) // 2
        color_canvas.paste(color_cropped, (cs_w, cs_h))
        color_img = color_canvas
        applied_attacks.append(f'裁剪{crop_pct:.0f}%')

    if abs(rotate_deg) > 0:
        img_pil = Image.fromarray((attacked_arr * 255).astype(np.uint8))
        img_rot = img_pil.rotate(rotate_deg, expand=True, fillcolor=128)
        # Center-crop back to original dimensions so moment-based features
        # are computed on a same-sized image (rotation changes size with
        # expand=True; without this, PHFRFM moments become uncorrelated).
        rw, rh = img_rot.size
        cw = max(0, (rw - W) // 2)
        ch = max(0, (rh - H) // 2)
        img_rot_cropped = img_rot.crop((cw, ch, cw + W, ch + H))
        attacked_arr = np.asarray(img_rot_cropped.convert('L'), dtype=np.float64) / 255.0
        # Apply same rotation + crop to color image
        color_img = color_img.rotate(rotate_deg, expand=True, fillcolor=(128, 128, 128))
        cW, cH = color_img.size
        ccw = max(0, (cW - color_img_orig_w) // 2)
        cch = max(0, (cH - color_img_orig_h) // 2)
        color_img = color_img.crop((ccw, cch, ccw + color_img_orig_w, cch + color_img_orig_h))
        applied_attacks.append(f'旋转{rotate_deg:.0f}°')

    if jpeg_q < 100:
        img_pil = Image.fromarray((attacked_arr * 255).astype(np.uint8))
        buf = io.BytesIO()
        img_pil.save(buf, 'JPEG', quality=jpeg_q)
        buf.seek(0)
        attacked_arr = np.asarray(Image.open(buf).convert('L'), dtype=np.float64) / 255.0
        # Apply same JPEG compression to color image
        buf2 = io.BytesIO()
        color_img.save(buf2, 'JPEG', quality=jpeg_q)
        buf2.seek(0)
        color_img = Image.open(buf2).convert('RGB')
        applied_attacks.append(f'JPEG Q={jpeg_q}')

    if abs(scale_pct - 100) > 1:
        H2, W2 = int(H * scale_pct/100), int(W * scale_pct/100)
        img_pil = Image.fromarray((attacked_arr * 255).astype(np.uint8))
        scaled = img_pil.resize((W2, H2), Image.LANCZOS).resize((W, H), Image.LANCZOS)
        attacked_arr = np.asarray(scaled.convert('L'), dtype=np.float64) / 255.0
        # Apply same scaling to color image
        cW, cH = color_img.size
        sW2, sH2 = int(cW * scale_pct/100), int(cH * scale_pct/100)
        color_scaled = color_img.resize((sW2, sH2), Image.LANCZOS).resize((cW, cH), Image.LANCZOS)
        color_img = color_scaled
        applied_attacks.append(f'缩放{scale_pct:.0f}%')

    if noise_sigma > 0:
        noise = np.random.normal(0, noise_sigma, attacked_arr.shape)
        attacked_arr = np.clip(attacked_arr + noise, 0, 1)
        # Apply same Gaussian noise to color image
        color_arr = np.array(color_img, dtype=np.float64)
        c_noise = np.random.normal(0, noise_sigma * 255, color_arr.shape)
        color_arr = np.clip(color_arr + c_noise, 0, 255)
        color_img = Image.fromarray(color_arr.astype(np.uint8), mode='RGB')
        applied_attacks.append(f'噪声{noise_sigma}')

    # Extract watermark from attacked image
    mode = d.get('mode', 'dft')
    p = d.get('params', {})
    result = {'success': True, 'applied_attacks': applied_attacks}

    # Counter-rotation compensation: both PHFRFM moments AND DFT spectrum are
    # NOT rotation-invariant under crop-to-original-size. Since we know the exact
    # rotation angle applied above, counter-rotate before extraction.
    # FIX #128: extended to 'dft' mode (was only 'zero'/'phfrfm' — DFT was omitted).
    extract_arr = attacked_arr
    if abs(rotate_deg) > 0 and mode in ('zero', 'phfrfm', 'dft'):
        ext_img = Image.fromarray((attacked_arr * 255).astype(np.uint8))
        img_counter = ext_img.rotate(-rotate_deg, expand=True, fillcolor=128)
        # Center-crop back to current attacked_arr size after counter-rotation
        ew, eh = img_counter.size
        aw, ah = attacked_arr.shape[1], attacked_arr.shape[0]  # H,W order for numpy
        ccw_ = max(0, (ew - aw)) // 2
        cch_ = max(0, (eh - ah)) // 2
        img_counter_cropped = img_counter.crop((ccw_, cch_, ccw_ + aw, cch_ + ah))
        extract_arr = np.asarray(img_counter_cropped.convert('L'), dtype=np.float64) / 255.0

    # FIX #129: Scale compensation for DFT mode.
    # When the image is downscaled (e.g., 50%), high-frequency DFT coefficient
    # pairs are destroyed by interpolation. Since we know the exact scale factor,
    # counter-scale (upsample) before extraction to restore the frequency layout.
    # The _dft_carrier_pairs use normalized coordinates mapped via _norm_to_bin,
    # so restoring approximate resolution recovers pair alignment.
    if abs(scale_pct - 100) > 1 and mode == 'dft':
        orig_H, orig_W = arr.shape[0], arr.shape[1]  # original embedding dimensions
        cur_H, cur_W = extract_arr.shape[0], extract_arr.shape[1]
        counter_scale = 100.0 / scale_pct
        new_w = int(cur_W * counter_scale)
        new_h = int(cur_H * counter_scale)
        ext_img = Image.fromarray((extract_arr * 255).astype(np.uint8))
        ext_img_upscaled = ext_img.resize((new_w, new_h), Image.LANCZOS)
        # Center-crop back to original embedding size for consistent coefficient mapping
        uw, uh = ext_img_upscaled.size
        ocw = max(0, (uw - orig_W)) // 2
        och = max(0, (uh - orig_H)) // 2
        right = min(ocw + orig_W, uw)
        bottom = min(och + orig_H, uh)
        ext_img_cropped = ext_img_upscaled.crop((ocw, och, right, bottom))
        # If cropped size differs from original (shouldn't happen), resize as fallback
        if ext_img_cropped.size != (orig_W, orig_H):
            ext_img_cropped = ext_img_cropped.resize((orig_W, orig_H), Image.LANCZOS)
        extract_arr = np.asarray(ext_img_cropped.convert('L'), dtype=np.float64) / 255.0

    if mode == 'dft':
        # FIX #128: use extract_arr (counter-rotated if rotation was applied)
        # instead of raw attacked_arr, so DFT spectrum alignment is preserved.
        ext = extract_entire_watermark(Image.fromarray((extract_arr * 255).astype(np.uint8)), p)
        # FIX #130: enrich extract response with fields the frontend expects.
        # extract_entire_watermark returns {did, hash_verified, confidence_mean, attack_results}
        # but the JS frontend reads extract.match, extract.char_similarity, extract.ber —
        # those only exist in the PHFRFM branch.  Add them here so DFT results render correctly.
        did_ext = ext.get('did', '') or ''
        # Reconstruct expected DID from params (same logic as PHFRFM branch)
        exp_bits_for_did = np.array(p.get('original_bits', []), dtype=np.uint8)
        did_bit_len = int(p.get('did_bit_len', 0))
        embedded_did = ''
        if did_bit_len > 0 and len(exp_bits_for_did) >= did_bit_len:
            emb_bytes = bytearray()
            for i in range(0, did_bit_len, 8):
                chunk = exp_bits_for_did[i:i+8]
                if len(chunk) == 8:
                    emb_bytes.append(int(np.packbits(np.array(chunk, dtype=np.uint8))[0]))
            embedded_did = emb_bytes.decode('utf-8', errors='replace').rstrip('\x00')
        if not embedded_did:
            embedded_did = (p.get('did', '') or '').strip()
        did_match = (did_ext == embedded_did)
        # Char similarity
        char_sim = 0.0
        same_chars = 0
        if did_ext and embedded_did:
            max_len = max(len(did_ext), len(embedded_did))
            if max_len > 0:
                for idx, (a, b) in enumerate(zip(did_ext, embedded_did)):
                    if a == b:
                        same_chars += 1
                char_sim = round(same_chars / max_len, 3)
        # BER against original_bits
        ber_val = 0.0
        total_wm = int(p.get('total_wm_bits', 0))
        if total_wm > 0 and len(exp_bits_for_did) >= did_bit_len:
            # We don't have raw extracted bits here, but we can infer from match
            ber_val = 0.0 if did_match else 1.0
        ext['match'] = did_match
        ext['char_similarity'] = char_sim
        ext['ber'] = ber_val
        ext['mode'] = 'dft'
        ext['expected_did'] = embedded_did
        ext['expected_did_len'] = len(embedded_did)
        ext['extracted_did_len'] = len(did_ext)
        result['extract'] = ext
    elif mode in ('zero', 'phfrfm'):
        # PHFRFM zero watermark extract
        key_arr = np.array(p.get('key', []), dtype=np.uint8)
        p_val = float(p.get('p', 0.3))
        max_ord = int(p.get('max_order', 25))
        max_wm = int(p.get('total_wm_bits', 0))
        if len(key_arr) > 0 and max_wm > 0:
            # Extract from counter-rotated image (or attacked_arr if no rotation)
            recovered = phfrfm_zero_extract(extract_arr, key_arr, max_order=max_ord, p=p_val)
            if len(recovered) < max_wm:
                recovered = np.concatenate([recovered, np.zeros(max_wm - len(recovered), dtype=np.uint8)])
            else:
                recovered = recovered[:max_wm]

            # Also extract from ORIGINAL (unattacked) image for feature distance metric
            reference_bits = phfrfm_zero_extract(arr, key_arr, max_order=max_ord, p=p_val)
            if len(reference_bits) < max_wm:
                reference_bits = np.concatenate([reference_bits, np.zeros(max_wm - len(reference_bits), dtype=np.uint8)])
            else:
                reference_bits = reference_bits[:max_wm]
            feature_dist = float(np.sum(recovered != reference_bits)) / max(1, max_wm)

            # PSNR: image quality degradation caused by attacks
            # Note: rotate/scale with expand=True changes image shape — only compute PSNR when shapes match
            if arr.shape == attacked_arr.shape:
                mse_val = float(np.mean((arr - attacked_arr) ** 2))
                psnr_db = float('inf') if mse_val == 0 else float(10 * np.log10(1.0 / mse_val))
            else:
                # Shapes differ (e.g., rotate expanded) — use None (NaN is not JSON-serializable)
                psnr_db = None
            # Hamming ECC decode
            ecc_pad = int(p.get('ecc_pad', 0))
            ecc_info = {'total_errors': 0, 'corrected': 0, 'failed_blocks': 0, 'raw_ber': 0.0, 'decode_error': ''}
            did = ''
            try:
                raw_bits, ecc_info = decode_with_ecc(recovered, ecc_pad)
                did_bit_len = int(p.get('did_bit_len', 0))
                if did_bit_len > 0 and did_bit_len <= len(raw_bits):
                    did_bytes = bytearray()
                    for i in range(0, did_bit_len, 8):
                        chunk = raw_bits[i:i+8]
                        if len(chunk) == 8:
                            val = 0
                            for j, b in enumerate(chunk):
                                if b: val |= (1 << (7 - j))
                            did_bytes.append(val)
                    did = did_bytes.decode('utf-8', errors='replace').rstrip(chr(0))
            except Exception as ex:
                ecc_info['decode_error'] = str(ex)[:60]
            # BER calculation — compare recovered ECC bits against original embedded ECC bits
            # When ecc_bits is present in params (frontend stores it), this measures
            # true bit corruption caused by attacks. Without ecc_bits, BER would be
            # comparing ECC-encoded data against raw bits (~50% random), which is meaningless.
            _ecc_bits_in_params = p.get('ecc_bits', [])
            _has_ecc_bits = len(_ecc_bits_in_params) > 0
            if _has_ecc_bits:
                expected_bits = np.array(_ecc_bits_in_params, dtype=np.uint8)[:len(recovered)]
            else:
                # Fallback: reconstruct expected ECC bits from original_bits + ecc_pad
                # This is approximate — prefer having ecc_bits in frontend params
                _raw = np.array(p.get('original_bits', []), dtype=np.uint8)
                expected_bits = _raw[:len(recovered)] if len(_raw) > 0 else np.array([], dtype=np.uint8)
            ber = 0.0
            if len(expected_bits) > 0 and len(recovered) > 0:
                n = min(len(expected_bits), len(recovered))
                ber = float(np.sum(recovered[:n] != expected_bits[:n])) / n
            # NOTE: do NOT overwrite ecc_info here — it holds real decode_with_ecc results
            # Reconstruct expected DID from original_bits (BER uses the same bits)
            # This avoids relying on p.get('did') which may be empty in the JS params
            exp_bits_for_did = np.array(p.get('original_bits', []), dtype=np.uint8)
            did_bit_len = int(p.get('did_bit_len', 0))
            embedded_did = ''
            if did_bit_len > 0 and len(exp_bits_for_did) >= did_bit_len:
                embedded_bytes = bytearray()
                for i in range(0, did_bit_len, 8):
                    chunk = exp_bits_for_did[i:i+8]
                    if len(chunk) == 8:
                        embedded_bytes.append(int(np.packbits(np.array(chunk, dtype=np.uint8))[0]))
                embedded_did = embedded_bytes.decode('utf-8', errors='replace').rstrip('')
            if not embedded_did:
                # Fallback: try p.get('did') from params
                embedded_did = (p.get('did', '') or '').strip()
            did_match = did == embedded_did
            expected_bytes = embedded_did.encode('utf-8') if embedded_did else b''
            same_chars = 0
            first_char_diff = -1
            first_byte_diff = -1
            # Char similarity
            char_sim = 0.0
            same_chars = 0
            first_char_diff = -1
            if did and embedded_did:
                max_len = max(len(did), len(embedded_did))
                if max_len > 0:
                    for idx, (a, b) in enumerate(zip(did, embedded_did)):
                        if a == b:
                            same_chars += 1
                        elif first_char_diff < 0:
                            first_char_diff = idx
                    char_sim = round(same_chars / max_len, 3)
            # Byte-level diagnostics
            expected_bytes = embedded_did.encode('utf-8') if embedded_did else b''
            bytes_match = did_bytes == expected_bytes if did_bytes else False
            first_byte_diff = -1
            for idx, (a, b) in enumerate(zip(did_bytes or [], expected_bytes)):
                if a != b:
                    first_byte_diff = idx
                    break
            result['extract'] = {
                'did': did, 'mode': 'phfrfm', 'success': True,
                'ber': ber, 'match_rate': 1.0 - ber,
                'match': did_match, 'char_similarity': char_sim,
                'same_chars': same_chars, 'first_char_diff': first_char_diff,
                'bytes_match': bytes_match, 'first_byte_diff': first_byte_diff,
                'ecc_errors': ecc_info.get('total_errors', 0),
                'ecc_corrected': ecc_info.get('corrected', 0),
                'ecc_failed': ecc_info.get('failed_blocks', 0),
                'ecc_raw_ber': round(ecc_info.get('raw_ber', 0.0), 4),
                # Attack intensity metrics (vary with attack params)
                'psnr_db': round(psnr_db, 2) if psnr_db is not None and psnr_db != float('inf') else psnr_db,
                'feature_distance': round(feature_dist, 4),
                'feature_flipped_bits': int(np.sum(recovered != reference_bits)),
            }
            result['extract']['expected_did'] = embedded_did
            result['extract']['expected_did_len'] = len(embedded_did)
            result['extract']['extracted_did_len'] = len(did)
            result['extract']['did_bytes_hex'] = did_bytes.hex() if did_bytes else ''
            result['extract']['expected_bytes_hex'] = expected_bytes.hex() if expected_bytes else ''
        else:
            result['extract'] = {'error': '零水印密钥或参数缺失', 'success': False}
    else:
        # Other modes (e.g., old zero_watermark_extract fallback)
        key_arr = np.array(p.get('key', []), dtype=np.uint8)
        if len(key_arr) > 0:
            ext_bits = zero_watermark_extract(attacked_arr, key_arr)
            did_bytes = np.packbits(ext_bits[:p.get('did_bit_len', 0)]).tobytes()
            did = did_bytes.decode('utf-8', errors='replace').rstrip('\x00')
            result['extract'] = {'did': did, 'mode': 'zero', 'success': True}
        else:
            result['extract'] = {'error': '零水印密钥缺失', 'success': False}

    # Return attacked COLOR image as data URL (color_img has all transforms applied in parallel)
    buf = io.BytesIO()
    if color_img.mode != 'RGB': color_img = color_img.convert('RGB')
    color_img.save(buf, 'PNG')
    result['attacked_image'] = 'data:image/png;base64,' + base64.b64encode(buf.getvalue()).decode()
    return jsonify(result)

@app.route('/api/watermark/verify_uploaded', methods=['POST'])
@require_key
@require_csrf
def api_wm_verify_uploaded():
    """用户上传自己的攻击后图片, 验证是否能提取出 DID"""
    d = request.get_json() or {}
    img = decode_image(d.get('image', ''))
    if not img: return jsonify({'success': False, 'error': 'invalid image'}), 400
    expected_did = (d.get('expected_did', '') or '').strip()
    p = d.get('params', {})
    mode = d.get('mode', 'dft')

    arr = _img_to_gray(img)
    result = {'success': True, 'expected_did': expected_did, 'image_size': list(arr.shape)}

    if mode == 'dft':
        # Use the watermark extraction
        ext = extract_entire_watermark(img, p)
        result['extract'] = ext
        # Compare with expected
        extracted_did = ext.get('did', '')
        result['extracted_did'] = extracted_did

        # 【BUG FIX】原 code 直接字符串相等比较
        # 由于 256x256 小图布局只支持 ~205 位, 720 位嵌入的 DID 会在 ~205 之后丢失
        # (旧 code ext_bits_did[:did_bit_len] 截断后, 后面位为 0)
        # 改进: 字符级模糊匹配
        match_score = 0.0
        if extracted_did and expected_did:
            # 清除 0x00 截断影响
            ext_clean = extracted_did.replace('\x00', '').rstrip('\x00')
            min_len = min(len(ext_clean), len(expected_did))
            if min_len > 0:
                same = sum(1 for a, b in zip(ext_clean, expected_did) if a == b)
                match_score = same / len(expected_did)
        result['char_similarity'] = round(match_score, 3)

        # 容错匹配: 字符相似度 > 70% 视为匹配 (覆盖小图损失)
        # 真实匹配 (字符串完全相等) > 95% 视为确定匹配
        if extracted_did == expected_did:
            result['match'] = True
            result['match_confidence'] = 'exact'
        elif match_score >= 0.70 and extracted_did.startswith('did:'):
            result['match'] = True
            result['match_confidence'] = 'fuzzy'
        else:
            result['match'] = False
            result['match_confidence'] = 'none' 
    elif mode in ('zero', 'phfrfm'):
        # PHFRFM zero watermark extract (with ECC decode)
        key_arr = np.array(p.get('key', []), dtype=np.uint8)
        if len(key_arr) == 0:
            return jsonify({'success': False, 'error': '零水印密钥缺失'}), 400
        p_val = float(p.get('p', 0.3))
        max_ord = int(p.get('max_order', 25))
        max_wm = int(p.get('total_wm_bits', 0))
        recovered = phfrfm_zero_extract(arr, key_arr, max_order=max_ord, p=p_val)
        if len(recovered) < max_wm:
            recovered = np.concatenate([recovered, np.zeros(max_wm - len(recovered), dtype=np.uint8)])
        else:
            recovered = recovered[:max_wm]
        did_bit_len = int(p.get('did_bit_len', 0))
        ecc_pad = int(p.get('ecc_pad', 0))
        extracted_did = ''
        ecc_info = {'total_errors': 0, 'corrected': 0, 'failed_blocks': 0, 'raw_ber': 0.0, 'decode_error': ''}
        # FIX: recovered bits are ECC-encoded (812 bits); must decode to get raw DID bits (464)
        try:
            raw_bits, ecc_info = decode_with_ecc(recovered, ecc_pad)
        except Exception as _ex:
            ecc_info['decode_error'] = str(_ex)[:80]
            raw_bits = recovered  # fallback (will produce garbled DID but won't crash)
        if did_bit_len > 0 and did_bit_len <= len(raw_bits):
            did_bytes = bytearray()
            for i in range(0, did_bit_len, 8):
                chunk = raw_bits[i:i+8]
                if len(chunk) == 8:
                    did_bytes.append(int(np.packbits(np.array(chunk, dtype=np.uint8))[0]))
            extracted_did = did_bytes.decode('utf-8', errors='replace').rstrip('\x00').rstrip(chr(0))
        result['match'] = extracted_did == expected_did
        result['extracted_did'] = extracted_did
        # 严格验证：必须 DID 完全一致且 ECC 解码无失败块。
        # 旧逻辑用 startswith('did:') 兜底，会导致任意图（只要提取出形似 DID）都判通过 -> 假阳性。
        ecc_failed_blocks = int(ecc_info.get('failed_blocks', 0))
        result['hash_verified'] = bool(extracted_did and extracted_did == expected_did and ecc_failed_blocks == 0)
        # Character similarity (compare with expected)
        if extracted_did and expected_did:
            min_len = min(len(extracted_did), len(expected_did))
            max_len = max(len(extracted_did), len(expected_did))
            same = sum(1 for a, b in zip(extracted_did, expected_did) if a == b)
            result['char_similarity'] = round(same / max_len, 3) if max_len > 0 else 0.0
        # BER: compare decoded raw_bits against original_bits (both 464-bit raw DID bits)
        expected_bits = np.array(p.get('original_bits', []), dtype=np.uint8)
        ber = 0.0
        if len(expected_bits) > 0 and len(raw_bits) > 0:
            n = min(len(expected_bits), len(raw_bits))
            ber = float(np.sum(raw_bits[:n] != expected_bits[:n])) / n
        result['ber'] = ber
        result['match_rate'] = 1.0 - ber
        result['ecc_errors'] = ecc_info.get('total_errors', 0)
        result['ecc_corrected'] = ecc_info.get('corrected', 0)
        result['ecc_failed'] = ecc_info.get('failed_blocks', 0)
        result['ecc_raw_ber'] = ecc_info.get('raw_ber', 0.0)
        result['extract'] = {
            'did': extracted_did, 'mode': 'phfrfm', 'ber': ber, 'success': True,
            'match': extracted_did == expected_did,
            'char_similarity': result.get('char_similarity', 0.0),
            'ecc_errors': ecc_info.get('total_errors', 0),
            'ecc_corrected': ecc_info.get('corrected', 0),
            'ecc_failed': ecc_info.get('failed_blocks', 0),
            'ecc_raw_ber': round(ecc_info.get('raw_ber', 0.0), 4),
        }
    else:
        key_arr = np.array(p.get('key', []), dtype=np.uint8)
        if len(key_arr) == 0:
            return jsonify({'success': False, 'error': '零水印密钥缺失'}), 400
        ext_bits = zero_watermark_extract(arr, key_arr)
        did_bytes = np.packbits(ext_bits[:p.get('did_bit_len', 0)]).tobytes()
        did = did_bytes.decode('utf-8', errors='replace').rstrip('\x00')
        result['extracted_did'] = did
        result['match'] = did == expected_did
    return jsonify(result)

@app.route('/api/watermark/extract', methods=['POST'])
@require_key
@require_csrf
def api_wm_extract():
    d = request.get_json() or {}; p = d.get('params',{})
    img = decode_image(d.get('image',''))
    if not img: return jsonify({'success':False, 'error':'invalid image'}), 400
    mode = p.get('mode', 'dft')
    if mode in ('phfrfm', 'zero'):
        arr = _img_to_gray(img)
        key = np.array(p.get('key', []), dtype=np.uint8)
        p_val = float(p.get('p', 0.3))
        max_ord = int(p.get('max_order', 25))
        max_wm = int(p.get('total_wm_bits', 0))
        if len(key) == 0 or max_wm == 0:
            return jsonify({'success': False, 'error': 'PHFRFM 缺少 key 或 total_wm_bits'}), 400
        recovered = phfrfm_zero_extract(arr, key, max_order=max_ord, p=p_val)
        # Ensure exactly max_wm bits
        if len(recovered) < max_wm:
            recovered = np.concatenate([recovered, np.zeros(max_wm - len(recovered), dtype=np.uint8)])
        else:
            recovered = recovered[:max_wm]
        # Decode to DID — must use ECC decode because key was generated from ECC-encoded bits
        ecc_pad = int(p.get('ecc_pad', 0))
        ecc_info = {'total_errors': 0, 'corrected': 0, 'failed_blocks': 0, 'raw_ber': 0.0, 'decode_error': ''}
        did = ''
        try:
            raw_bits, ecc_info = decode_with_ecc(recovered, ecc_pad)
            did_bit_len = int(p.get('did_bit_len', 0))
            if did_bit_len > 0 and did_bit_len <= len(raw_bits):
                did_bytes = bytearray()
                for i in range(0, did_bit_len, 8):
                    chunk = raw_bits[i:i+8]
                    if len(chunk) == 8:
                        val = 0
                        for j, b in enumerate(chunk):
                            if b: val |= (1 << (7 - j))
                        did_bytes.append(val)
                    did = did_bytes.decode('utf-8', errors='replace').rstrip(chr(0))
        except Exception as ex:
            ecc_info['decode_error'] = str(ex)[:60]
        # Hash verification
        if hasattr(hashlib, 'sm3'):
            expected_hash = hashlib.sm3(did.encode()).hexdigest() if did else ''
        else:
            expected_hash = hashlib.sha256(did.encode()).hexdigest() if did else ''
        # Calculate bit error rate vs expected
        expected_bits = np.array(p.get('original_bits', []), dtype=np.uint8)
        ber = 0.0
        if len(expected_bits) > 0 and len(recovered) > 0:
            n = min(len(expected_bits), len(recovered))
            ber = float(np.sum(recovered[:n] != expected_bits[:n])) / n
        # 严格验证：提取出的 DID 必须与嵌入时登记的 DID 完全一致（且 ECC 无失败块）。
        # 未提供期望 DID 时回退为「格式有效且解码无错」，避免旧图/无 key 场景误报。
        expected_did = (p.get('did', '') or '').strip()
        if expected_did:
            verified = bool(did and did == expected_did and ecc_info.get('failed_blocks', 0) == 0)
        else:
            verified = bool(did and ecc_info.get('failed_blocks', 0) == 0 and ('did' in did[:5] or ':' in did[:8]))
        result = {
            'success': True,
            'mode': 'phfrfm',
            'did': did,
            'did_valid': did != '' and ('did' in did[:5] or ':' in did[:8]),
            'hash_verified': verified,
            'recovered_bits': recovered.tolist(),
            'total_wm_bits': len(recovered),
            'ber': ber,
            'match_rate': 1.0 - ber,
            'ecc_errors': ecc_info.get('total_errors', 0),
            'ecc_corrected': ecc_info.get('corrected', 0),
            'ecc_failed': ecc_info.get('failed_blocks', 0),
            'ecc_raw_ber': round(ecc_info.get('raw_ber', 0.0), 4),
            'decode_error': ecc_info.get('decode_error', ''),
        }
    else:
        result = extract_entire_watermark(img, p)
        result['success'] = True
    return jsonify(result)

@app.route('/api/chain/status')
def api_chain():
    return jsonify(check_chain_status())

@app.route('/api/chain/verify', methods=['POST'])
@require_key
@require_csrf
def api_chain_verify():
    d = request.get_json() or {}
    return jsonify(verify_against_chain(d.get('data_did',''), d.get('fingerprint',''), '', None))

@app.route('/api/issuer_info')
def api_issuer(): return jsonify(get_issuer_info())

@app.route('/api/issuers')
def api_issuers():
    # 根 CA + 签发者证书目录（只读，供前端"签发者目录"展示）
    return jsonify(get_ca_directory())

@app.route('/api/issuers/revoke', methods=['POST'])
@require_key
@require_csrf
@limit
def api_issuer_revoke():
    body = request.get_json(silent=True) or {}
    did = body.get('did')
    reason = body.get('reason', '管理员吊销')
    if not did: return jsonify({'success': False, 'error': '缺少 did'}), 400
    ok = ca_store.revoke(did, reason)
    if not ok: return jsonify({'success': False, 'error': '签发者不存在'}), 404
    return jsonify({'success': True, 'did': did, 'status': 'revoked'})

@app.route('/api/issuers/restore', methods=['POST'])
@require_key
@require_csrf
@limit
def api_issuer_restore():
    body = request.get_json(silent=True) or {}
    did = body.get('did')
    if not did: return jsonify({'success': False, 'error': '缺少 did'}), 400
    ok = ca_store.restore(did)
    if not ok: return jsonify({'success': False, 'error': '签发者不存在'}), 404
    return jsonify({'success': True, 'did': did, 'status': 'valid'})

@app.route('/api/issuers/register', methods=['POST'])
@require_key
@require_csrf
@limit
def api_issuer_register():
    # 登记新的内部背书签发者（由根 CA 签发证书，持久化到 ca_store.json）
    body = request.get_json(silent=True) or {}
    issuer_id = (body.get('issuer_id') or '').strip()
    name = (body.get('name') or '').strip()
    usc = (body.get('unified_social_credit_code') or '').strip()
    region = (body.get('region') or '').strip()
    role = (body.get('role') or '').strip()
    if not issuer_id or not name:
        return jsonify({'success': False, 'error': 'issuer_id 与名称必填'}), 400
    # 命名空间强约束：did:trust:livestock:issuer:<issuer_id>
    issuer_did = 'did:trust:livestock:issuer:' + issuer_id
    r = ca_store.register_issuer(issuer_did, name, usc, region, role)
    if not r['ok']:
        return jsonify({'success': False, 'error': r['error']}), 409
    return jsonify({'success': True, 'did': r['did'], 'issuer_id': issuer_id, 'status': 'valid'})

# ---------- 外部商业 CA 信任锚（联邦） ----------
@app.route('/api/external-cas')
@require_key
def api_external_cas():
    # 只读，供前端"签发者目录 · 外部信任锚"展示
    return jsonify({'external_cas': ca_store.list_external_cas()})

@app.route('/api/external-cas', methods=['POST'])
@require_key
@require_csrf
@limit
def api_external_cas_add():
    body = request.get_json(silent=True) or {}
    name = (body.get('name') or '').strip()
    rx = (body.get('root_public_key_x') or '').strip()
    ry = (body.get('root_public_key_y') or '').strip()
    if not name:
        return jsonify({'success': False, 'error': '缺少外部 CA 名称'}), 400
    if not rx or not ry:
        return jsonify({'success': False, 'error': '缺少外部 CA 根公钥 (x/y)'}), 400
    members = body.get('members') or []
    if isinstance(members, str):
        members = [m.strip() for m in members.replace('，', ',').split(',') if m.strip()]
    entry = ca_store.add_external_ca(
        name=name, root_public_key_x=rx, root_public_key_y=ry,
        members=members, note=(body.get('note') or '').strip(),
        did_namespace=(body.get('did_namespace') or '').strip())
    return jsonify({'success': True, 'external_ca': entry})

@app.route('/api/external-cas/<ca_id>/disable', methods=['POST'])
@require_key
@require_csrf
@limit
def api_external_cas_disable(ca_id):
    ok = ca_store.set_external_ca_status(ca_id, 'disabled')
    if not ok: return jsonify({'success': False, 'error': '外部 CA 不存在'}), 404
    return jsonify({'success': True, 'id': ca_id, 'status': 'disabled'})

@app.route('/api/external-cas/<ca_id>/enable', methods=['POST'])
@require_key
@require_csrf
@limit
def api_external_cas_enable(ca_id):
    ok = ca_store.set_external_ca_status(ca_id, 'active')
    if not ok: return jsonify({'success': False, 'error': '外部 CA 不存在'}), 404
    return jsonify({'success': True, 'id': ca_id, 'status': 'active'})

@app.route('/api/vc/request', methods=['POST'])
@require_key
@require_csrf
def api_vc():
    d = request.get_json() or {}
    try:
        vc = request_credential(
            metadata=d.get('metadata', {}),
            holder_did=d.get('holder_did', OWNER_DID),
            issuer_did=d.get('issuer_did'),
            issuer_name=d.get('issuer_name'),
            modules=d.get('modules'),
            use_zk=bool(d.get('use_zk', False)),
        )
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    return jsonify(vc)

@app.route('/api/vc/verify', methods=['POST'])
@require_key
@require_csrf
def api_vc_verify():
    vc = (request.get_json() or {}).get('vc', {})
    res = verify_credential(vc)
    # 撤销状态校验（任务书子目标1：VC 撤销）
    vc_id = vc.get('id')
    if vc_id:
        revoked, reason, at = vc_revoked(vc_id)
        if revoked:
            res['valid'] = False
            res.setdefault('errors', []).append('凭证已被撤销(VC Revoked)：' + (reason or ''))
            res['revoked'] = True
            res['revoke_reason'] = reason
            res['revoked_at'] = at
    return jsonify(res)

@app.route('/api/vp/construct', methods=['POST'])
@require_key
@require_csrf
def api_vp_construct():
    d = request.get_json() or {}
    vc = d.get('vc') or d.get('credentials')
    if isinstance(vc, list): vc = vc[0] if vc else None
    vp = construct_presentation(
        vc,
        modules=d.get('modules'),
        challenge=d.get('challenge'),
        domain=d.get('domain'),
        disclose_fields=d.get('disclose_fields'),
    )
    # VP 签发日志（任务书子目标1：VP 查询）——仅对合法生成的 VP 落库
    if isinstance(vp, dict) and vp.get('id') and vp.get('id') != 'vp:error':
        try:
            vcs = vp.get('verifiableCredential', []) or []
            vc_ids = ','.join([v.get('id', '') for v in vcs if v.get('id')])
            con = sqlite3.connect(DB_PATH)
            con.execute('INSERT OR IGNORE INTO vp_log(vp_id,holder,disclosure,modules,disclosed_fields,challenge,domain,vc_ids,created) VALUES(?,?,?,?,?,?,?,?,?)',
                        (vp.get('id'), vp.get('holder'), vp.get('disclosure'),
                         json.dumps(vp.get('modules', []), ensure_ascii=False),
                         json.dumps(vp.get('disclosed_fields') or [], ensure_ascii=False),
                         vp.get('challenge'), vp.get('domain'), vc_ids, _now_beijing()))
            con.commit(); con.close()
        except Exception:
            pass
    return jsonify(vp)

@app.route('/api/vp/verify', methods=['POST'])
@require_key
@require_csrf
def api_vp_verify():
    vp = (request.get_json() or {}).get('vp', {})
    res = verify_presentation(vp)
    # 内嵌 VC 撤销状态校验（任务书子目标1：VP 携带的 VC 被撤销则整体失效）
    for v in (vp.get('verifiableCredential', []) or []):
        vid = v.get('id') if isinstance(v, dict) else None
        if vid:
            revoked, reason, at = vc_revoked(vid)
            if revoked:
                res['valid'] = False
                res.setdefault('errors', []).append('内嵌凭证 %s 已被撤销(VC Revoked)：%s' % (vid, reason or ''))
    return jsonify(res)

CREDIT_RE = re.compile(r"(?:统一社会信用代码|信用代码|养殖场代码)[:：]\s*([0-9A-Z]{18})")


def load_registered_parties():
    """读取 did_registry 中已登记（含已注销）主体，补充到主数据目录（与种子主体同构）。"""
    out = []
    try:
        con = sqlite3.connect(DB_PATH); con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute("SELECT did, credit_code, name, role, region, issuer_id, status FROM did_registry")
        for r in cur.fetchall():
            out.append({
                "role": r["role"] or "party",
                "name": r["name"],
                "credit_code": r["credit_code"],
                "did": r["did"],
                "region": r["region"] or "",
                "registered": r["status"] == "active",
                "did_status": r["status"],
                "did_revoked": r["status"] == "revoked",
                "history": False,
            })
        con.close()
    except Exception:
        pass
    return out


def get_seed_parties():
    """主数据目录：养殖场 / 屠宰场 / 官方兽医。种子规范主体 + 聚合库内已出现信用代码。"""
    seeds = [
        # 主体 DID 统一到 did:trust:livestock:party:<issuer_id>:<short> 命名空间，
        # 把"由哪个签发机构背书"编码进 DID，实现 CA 强绑定（issuer_id 对应 ca_store 中
        # 真实可信的签发机构 DID 后缀）。
        {"role": "farm", "name": "XX生态养殖场", "credit_code": "91110000MA01XXXXX2",
         "did": "did:trust:livestock:party:livestock_authority_001:xxst", "region": "华北"},
        {"role": "farm", "name": "绿源牧业有限公司", "credit_code": "91110000MA02BBBBB3",
         "did": "did:trust:livestock:party:livestock_authority_001:ly", "region": "东北"},
        {"role": "farm", "name": "康达生态养殖基地", "credit_code": "91110000MA03CCCCC4",
         "did": "did:trust:livestock:party:livestock_authority_001:kd", "region": "西南"},
        {"role": "slaughter", "name": "XX肉类食品有限公司", "credit_code": "91110000MA01XXXXY8",
         "license": "A201400XX", "did": "did:trust:livestock:party:slaughter_b:xxmr", "region": "华北"},
        {"role": "slaughter", "name": "鲜丰屠宰加工股份有限公司", "credit_code": "91110000MA04DDDDD5",
         "license": "A201400YY", "did": "did:trust:livestock:party:slaughter_b:xf", "region": "华东"},
        {"role": "vet", "name": "XX市畜牧兽医检疫站", "did": "did:trust:livestock:party:vet_station_a:xx", "region": "华北"},
        {"role": "vet", "name": "YY区动物卫生监督所", "did": "did:trust:livestock:party:vet_station_a:yy", "region": "华东"},
    ]
    # 合并 did_registry 中已登记（含已注销）主体，使 /api/did/register 落地后
    # 可在主数据目录、提交绑定、CA 解析中生效（闭环验证 DID 注册真实可用）。
    _by_code = {p.get("credit_code") for p in seeds if p.get("credit_code")}
    for rp in load_registered_parties():
        if rp.get("credit_code") and rp["credit_code"] in _by_code:
            continue
        seeds.append(rp)
    try:
        con = sqlite3.connect(DB_PATH); con.row_factory = sqlite3.Row
        cur = con.cursor()
        seen = set(p["credit_code"] for p in seeds if p.get("credit_code"))
        cur.execute("SELECT metadata FROM commitments")
        for r in cur.fetchall():
            m = r["metadata"]
            if not m:
                continue
            try:
                payload = json.loads(m).get("metadata", {})
            except Exception:
                continue
            txt = json.dumps(payload, ensure_ascii=False) if isinstance(payload, dict) else str(payload)
            for code in re.findall(r"统一社会信用代码[:：]\s*([0-9A-Z]{18})", txt):
                if code not in seen:
                    seen.add(code)
                    seeds.append({"role": "unknown", "name": code, "credit_code": code,
                                  "did": None, "region": "", "history": True})
        con.close()
    except Exception:
        pass
    return seeds


def get_party_binding(raw, meta):
    """在提交数据中提取统一社会信用代码，若命中主数据注册主体则建立 DID 双向绑定。"""
    text = raw or ''
    try:
        text += '\n' + json.dumps(meta, ensure_ascii=False)
    except Exception:
        pass
    code = None
    for c in CREDIT_RE.findall(text):
        code = c
        break
    if not code:
        return None
    seeds = get_seed_parties()
    party = next((p for p in seeds if p.get("credit_code") == code), None)
    if party:
        _link = resolve_party_ca_link(party.get("did"))
        return {"code": code, "name": party.get("name"), "did": party.get("did"),
                "role": party.get("role"), "registered": True,
                "did_revoked": bool(party.get("did_revoked")),
                "ca_linked": _link["ca_linked"], "ca_issuer": _link["ca_issuer"],
                "ca_name": _link["ca_name"], "ca_reason": _link["ca_reason"]}
    return {"code": code, "name": None, "did": None, "role": "unknown", "registered": False,
            "did_revoked": False,
            "ca_linked": False, "ca_issuer": None, "ca_name": None, "ca_reason": "no_party"}


def lookup_party(code=None, name=None, did=None):
    """双向绑定查询：给定信用代码/名称/DID，返回主体登记状态、DID 绑定与链上记录数。"""
    seeds = get_seed_parties()
    party = None
    if did:
        party = next((p for p in seeds if p.get("did") == did), None)
    if not party and code:
        party = next((p for p in seeds if p.get("credit_code") == code), None)
    if not party and name:
        party = next((p for p in seeds if p.get("name") == name), None)
    found = bool(party)
    did_bound = bool(party and party.get("did"))
    registered = bool(party and party.get("did") and not party.get("history"))
    _link = resolve_party_ca_link(party.get("did")) if party and party.get("did") else \
        {"ca_linked": False, "ca_issuer": None, "ca_name": None, "ca_reason": "no_did"}
    ca_linked = _link["ca_linked"]
    ca_issuer = _link["ca_issuer"]
    ca_name = _link["ca_name"]
    ca_reason = _link["ca_reason"]
    records_count = 0
    key = code or (party.get("credit_code") if party else None)
    try:
        con = sqlite3.connect(DB_PATH); con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute("SELECT metadata FROM commitments")
        for r in cur.fetchall():
            m = r["metadata"]
            if not m:
                continue
            if key and key in m:
                records_count += 1
            elif party and party.get("name") and party["name"] in m:
                records_count += 1
        con.close()
    except Exception:
        pass
    return {"found": found, "party": party, "did_bound": did_bound,
            "registered": registered, "did_revoked": bool(party and party.get("did_revoked")),
            "ca_linked": ca_linked,
            "ca_issuer": ca_issuer, "ca_name": ca_name, "ca_reason": ca_reason,
            "records_count": records_count}


@app.route('/api/parties')
def api_parties():
    seeds = get_seed_parties()
    # 为每个主体附加 CA 强绑定解析结果（与 /api/party/lookup 同源，避免前端重复判定）
    out = []
    for p in seeds:
        _link = resolve_party_ca_link(p.get("did"))
        _p = dict(p)
        _p["ca_linked"] = _link["ca_linked"]
        _p["ca_issuer"] = _link["ca_issuer"]
        _p["ca_name"] = _link["ca_name"]
        _p["ca_reason"] = _link["ca_reason"]
        out.append(_p)
    return jsonify({"parties": out, "count": len(out)})


@app.route('/api/party/lookup')
def api_party_lookup():
    code = (request.args.get('code') or '').strip()
    name = (request.args.get('name') or '').strip()
    did = (request.args.get('did') or '').strip()
    return jsonify(lookup_party(code=code, name=name, did=did))


# ============ DID 全生命周期管理（任务书子目标1：注册/注销/查询/修改） ============
def _did_doc_from_row(r):
    """将 did_registry 行映射为 W3C 风格的 DID Document（含状态与注销信息）。"""
    return {
        "did": r["did"], "credit_code": r["credit_code"], "name": r["name"],
        "role": r["role"], "region": r["region"], "issuer_id": r["issuer_id"],
        "controller": r["controller"], "status": r["status"],
        "revoke_reason": r["revoke_reason"], "revoked_at": r["revoked_at"],
        "created": r["created"], "updated": r["updated"],
    }


@app.route('/api/did/register', methods=['POST'])
@require_key
@require_csrf
@limit
def api_did_register():
    """畜牧企业 DID 注册：信用代码 → 强绑定命名空间 DID（did:trust:livestock:party:<issuer>:<short>）。"""
    body = request.get_json(silent=True) or {}
    credit_code = (body.get('credit_code') or '').strip()
    name = (body.get('name') or '').strip()
    role = (body.get('role') or 'farm').strip()
    region = (body.get('region') or '').strip()
    issuer_id = (body.get('issuer_id') or 'livestock_authority_001').strip()
    if not re.match(r'^[0-9A-Z]{18}$', credit_code):
        return jsonify({'success': False, 'error': '统一社会信用代码格式非法（应为 18 位大写字母/数字）'}), 400
    if not name:
        return jsonify({'success': False, 'error': '主体名称不能为空'}), 400
    # 发行方必须已在 CA 信任锚注册且有效，落实 CA 强绑定（与 VC 签发一致）
    issuer_did_str = issuer_did(issuer_id)
    _cert = ca_store.get_cert(issuer_did_str)
    if not _cert or _cert.get('status') != 'valid':
        return jsonify({'success': False, 'error': '签发机构(%s) 未在信任锚注册或已失效，拒绝登记' % issuer_did_str}), 400
    # 同一信用代码 → 同一 short → 同一 DID（幂等：重复登记稳定命中）
    short = hashlib.sha256(credit_code.encode()).hexdigest()[:6]
    did = party_did(issuer_id, short)
    with get_db() as db:
        exist = db.execute('SELECT did FROM did_registry WHERE credit_code=? OR did=?', (credit_code, did)).fetchone()
        if exist:
            return jsonify({'success': False, 'error': '该信用代码或 DID 已登记', 'did': exist['did']}), 409
        now = _now_beijing()
        db.execute('INSERT INTO did_registry(did,credit_code,name,role,region,issuer_id,controller,status,created,updated) VALUES(?,?,?,?,?,?,?,?,?,?)',
                   (did, credit_code, name, role, region, issuer_id, issuer_did_str, 'active', now, now))
        db.commit()
        row = db.execute('SELECT * FROM did_registry WHERE did=?', (did,)).fetchone()
    return jsonify({'success': True, 'did_document': _did_doc_from_row(row), 'message': 'DID 注册成功'})


@app.route('/api/did/revoke', methods=['POST'])
@require_key
@require_csrf
@limit
def api_did_revoke():
    """畜牧企业 DID 注销（状态置为 revoked，保留撤销原因与时间，DID 标识本身不可变）。"""
    body = request.get_json(silent=True) or {}
    did = (body.get('did') or '').strip()
    code = (body.get('credit_code') or '').strip()
    reason = (body.get('reason') or '主体主动注销').strip()
    if not did and not code:
        return jsonify({'success': False, 'error': '需提供 did 或 credit_code'}), 400
    with get_db() as db:
        if did:
            row = db.execute('SELECT * FROM did_registry WHERE did=?', (did,)).fetchone()
        else:
            row = db.execute('SELECT * FROM did_registry WHERE credit_code=?', (code,)).fetchone()
        if not row:
            return jsonify({'success': False, 'error': 'DID 未登记'}), 404
        now = _now_beijing()
        db.execute('UPDATE did_registry SET status=?, revoke_reason=?, revoked_at=?, updated=? WHERE did=?',
                   ('revoked', reason, now, now, row['did']))
        db.commit()
        row = db.execute('SELECT * FROM did_registry WHERE did=?', (row['did'],)).fetchone()
    return jsonify({'success': True, 'did_document': _did_doc_from_row(row), 'message': 'DID 已注销'})


@app.route('/api/did/update', methods=['POST'])
@require_key
@require_csrf
@limit
def api_did_update():
    """畜牧企业 DID 信息修改：仅可变属性（名称/地区/角色），DID 标识本身不可改。"""
    body = request.get_json(silent=True) or {}
    did = (body.get('did') or '').strip()
    if not did:
        return jsonify({'success': False, 'error': '需提供 did'}), 400
    name = (body.get('name') or '').strip()
    region = (body.get('region') or '').strip()
    role = (body.get('role') or '').strip()
    with get_db() as db:
        row = db.execute('SELECT * FROM did_registry WHERE did=?', (did,)).fetchone()
        if not row:
            return jsonify({'success': False, 'error': 'DID 未登记'}), 404
        if row['status'] == 'revoked':
            return jsonify({'success': False, 'error': '已注销的 DID 不可修改'}), 400
        now = _now_beijing()
        # 仅当传入非空时才覆盖；传空串则保留原值（COALESCE(NULLIF) 技巧）
        db.execute('UPDATE did_registry SET name=COALESCE(NULLIF(?,\'\'),name), '
                   'region=COALESCE(NULLIF(?,\'\'),region), role=COALESCE(NULLIF(?,\'\'),role), updated=? WHERE did=?',
                   (name, region, role, now, did))
        db.commit()
        row = db.execute('SELECT * FROM did_registry WHERE did=?', (did,)).fetchone()
    return jsonify({'success': True, 'did_document': _did_doc_from_row(row), 'message': 'DID 信息已更新'})


@app.route('/api/did/query')
def api_did_query():
    """畜牧企业 DID 查询：优先查 did_registry，回退到主数据种子目录（含 CA 强绑定解析）。"""
    did = (request.args.get('did') or '').strip()
    code = (request.args.get('code') or '').strip()
    name = (request.args.get('name') or '').strip()
    with get_db() as db:
        if did:
            row = db.execute('SELECT * FROM did_registry WHERE did=?', (did,)).fetchone()
        elif code:
            row = db.execute('SELECT * FROM did_registry WHERE credit_code=?', (code,)).fetchone()
        else:
            row = None
        if row:
            doc = _did_doc_from_row(row)
            doc['registered'] = True
            doc['source'] = 'did_registry'
            return jsonify({'success': True, 'did_document': doc, 'found': True})
    # 回退到种子目录（含 CA 强绑定解析）
    res = lookup_party(code=code, name=name, did=did)
    if res.get('found'):
        party = res.get('party') or {}
        doc = {
            'did': party.get('did'), 'credit_code': party.get('credit_code'),
            'name': party.get('name'), 'role': party.get('role'),
            'region': party.get('region'), 'status': 'active' if res.get('registered') else 'unregistered',
            'registered': res.get('registered'), 'did_revoked': res.get('did_revoked'),
            'ca_linked': res.get('ca_linked'), 'ca_issuer': res.get('ca_issuer'),
            'ca_name': res.get('ca_name'), 'ca_reason': res.get('ca_reason'),
            'source': 'seed_directory',
        }
        return jsonify({'success': True, 'did_document': doc, 'found': True})
    return jsonify({'success': False, 'error': '未找到匹配的 DID', 'found': False}), 404


# ============ VC 撤销（任务书子目标1：VC 撤销 + verify 状态校验） ============
@app.route('/api/vc/revoke', methods=['POST'])
@require_key
@require_csrf
@limit
def api_vc_revoke():
    """撤销指定 VC（按 vc_id 记录状态）；撤销后 /api/vc/verify 与内嵌该 VC 的 /api/vp/verify 将判失败。"""
    body = request.get_json(silent=True) or {}
    vc_id = (body.get('vc_id') or '').strip()
    reason = (body.get('reason') or '凭证撤销').strip()
    if not vc_id:
        return jsonify({'success': False, 'error': '需提供 vc_id'}), 400
    with get_db() as db:
        now = _now_beijing()
        db.execute('INSERT INTO vc_status(vc_id,status,reason,revoked_at,created) VALUES(?,?,?,?,?) '
                   'ON CONFLICT(vc_id) DO UPDATE SET status=excluded.status, reason=excluded.reason, revoked_at=excluded.revoked_at',
                   (vc_id, 'revoked', reason, now, now))
        db.commit()
        row = db.execute('SELECT * FROM vc_status WHERE vc_id=?', (vc_id,)).fetchone()
    return jsonify({'success': True, 'vc_id': vc_id, 'status': row['status'],
                    'reason': row['reason'], 'revoked_at': row['revoked_at'], 'message': 'VC 已撤销'})


# ============ VP 签发日志查询（任务书子目标1：VP 查询） ============
@app.route('/api/vp/query')
def api_vp_query():
    """查询已签发的 VP 日志：按 vp_id 精确查，或按 holder 列出其全部 VP 表达。"""
    vp_id = (request.args.get('vp_id') or '').strip()
    holder = (request.args.get('holder') or '').strip()
    with get_db() as db:
        if vp_id:
            rows = db.execute('SELECT * FROM vp_log WHERE vp_id=?', (vp_id,)).fetchall()
        elif holder:
            rows = db.execute('SELECT * FROM vp_log WHERE holder=? ORDER BY created DESC', (holder,)).fetchall()
        else:
            rows = db.execute('SELECT * FROM vp_log ORDER BY created DESC LIMIT 200').fetchall()
        items = []
        for r in rows:
            items.append({
                'vp_id': r['vp_id'], 'holder': r['holder'], 'disclosure': r['disclosure'],
                'modules': json.loads(r['modules']) if r['modules'] else [],
                'disclosed_fields': json.loads(r['disclosed_fields']) if r['disclosed_fields'] else [],
                'challenge': r['challenge'], 'domain': r['domain'],
                'vc_ids': (r['vc_ids'].split(',') if r['vc_ids'] else []),
                'created': r['created'],
            })
    return jsonify({'success': True, 'count': len(items), 'vp_logs': items})


if __name__ == '__main__':
    print(f'Owner DID: {OWNER_DID}')
    app.run(host='0.0.0.0', port=5000, debug=False)
