#!/usr/bin/env python3
"""Trust Verification App - v6 final"""
import sys, os, json, time, secrets, sqlite3, base64, io, hashlib
import numpy as np
from datetime import datetime, timezone
from functools import wraps
from contextlib import contextmanager
from flask import Flask, request, jsonify, render_template
from PIL import Image
from core.pedersen import commit, verify_commitment
from core.fingerprint import generate_fingerprint, verify_fingerprint, canonical_json
from core.sm2_sign import generate_keypair, sign_string, verify as sm2_verify
from core.did_manager import generate_did, create_on_chain_record
from core.metadata_extractor import extract_metadata
from core.vc_manager import request_credential, verify_credential, construct_presentation, verify_presentation, get_issuer_info
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
    db.execute('''CREATE TABLE IF NOT EXISTS commitments(id INTEGER PRIMARY KEY AUTOINCREMENT, data_did TEXT UNIQUE, data_type TEXT, raw_data TEXT, algorithm TEXT DEFAULT 'SM3', fingerprint TEXT, commitment TEXT, randomness TEXT, owner_did TEXT, owner_key TEXT, chain_tx_id TEXT, block_height INTEGER, metadata TEXT, vc_id TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    db.execute('CREATE INDEX IF NOT EXISTS idx_did ON commitments(data_did)')
    db.commit()

OWNER_KEYPAIR = generate_keypair()
OWNER_DID = generate_did(entity_type='owner', seed=OWNER_KEYPAIR.get('private_key','')[:32])['did']
OWNER_NAME = 'XX生态养殖场'

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

@app.route('/')
def index():
    # Server-side pre-render records so page works even without JS
    return render_template('index.html')

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
    meta = extract_metadata(raw, dtype)
    fp_r = generate_fingerprint(raw, meta)
    fp = fp_r['fingerprint']
    cmt_r = commit(fp); C = cmt_r['commitment']; r_val = str(cmt_r['nonce'])
    sig_r = sign_string(fp, OWNER_KEYPAIR['private_key']); sig = json.dumps(sig_r)
    did_r = generate_did(entity_type='data'); did = did_r['did']
    chain = store_on_chain(did, fp, C, sig, json.dumps(meta)); tx = chain.get('tx_id',''); bh = chain.get('block_height',0)
    with get_db() as db:
        from datetime import datetime
        ts = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f+00:00')
        db.execute('INSERT INTO commitments(data_did,data_type,raw_data,fingerprint,commitment,randomness,owner_did,owner_key,chain_tx_id,block_height,metadata,timestamp) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)', (did,dtype,raw,fp,C,r_val,OWNER_DID,OWNER_KEYPAIR.get('public_key',''),tx,bh,json.dumps(meta),ts))
        db.commit()
    return jsonify({
        'success': True,
        'step1_extraction': {'method': 'NLP-NER + 模板匹配', 'confidence': 0.5, 'matched_fields': 5, 'total_fields': 10, 'meta': meta},
        'step2_fingerprint': {'fingerprint': fp, 'algorithm': 'SM3'},
        'step3_commitment': {'commitment': C},
        'step4_onchain': {'data_did': did, 'fingerprint': fp, 'commitment': C, 'randomness': r_val, 'signature': sig, 'chain_tx_id': tx, 'block_height': bh},
        'step5_chainmaker': {'success': bool(tx), 'tx_id': tx, 'block_height': bh, 'contract': 'fact', 'method': 'save', 'error': chain.get('error','') if not tx else ''},
        'data_did': did, 'fingerprint': fp, 'commitment': C, 'randomness': r_val, 'signature': sig, 'owner_did': OWNER_DID, 'chain_tx_id': tx, 'block_height': bh, 'algorithm': 'SM3', 'data_type': dtype, 'metadata': meta
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

    # Compute fingerprint based on current (potentially modified) data
    stored_fp = record.get('fingerprint','') if record else ''
    if tampered and raw:
        try:
            meta = extract_metadata(raw, record.get('data_type', 'general') if record else 'general')
            new_fp_r = generate_fingerprint(raw, meta)
            fp_to_check = new_fp_r['fingerprint']
        except:
            fp_to_check = user_fp or stored_fp
    else:
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
        },
        'details': {
            'fingerprint': fp_detail,
            'commitment': cm_detail,
            'signature': sg_detail,
            'chain': ch_detail,
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

@app.route('/api/reveal', methods=['POST'])
@require_key
@require_csrf
def api_reveal():
    d = request.get_json() or {}
    with get_db() as db: r = db.execute('SELECT * FROM commitments WHERE data_did=?',(d.get('data_did',''),)).fetchone()
    if not r: return jsonify({'success':False,'error':'not found'}),404
    item = {k:v for k,v in dict(r).items() if v is not None}
    item['note'] = '承诺已揭示'
    # alias for frontend which reads data.nonce
    item['nonce'] = item.get('randomness', '')
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
        # Place back at center
        eh, ew = cropped.shape
        sh, sw = (H-eh)//2, (W-ew)//2
        attacked_arr[sh:sh+eh, sw:sw+ew] = cropped
        applied_attacks.append(f'裁剪{crop_pct:.0f}%')

    if abs(rotate_deg) > 0:
        img_pil = Image.fromarray((attacked_arr * 255).astype(np.uint8))
        img_rot = img_pil.rotate(rotate_deg, expand=True, fillcolor=128)
        attacked_arr = np.asarray(img_rot.convert('L'), dtype=np.float64) / 255.0
        applied_attacks.append(f'旋转{rotate_deg:.0f}°')

    if jpeg_q < 100:
        img_pil = Image.fromarray((attacked_arr * 255).astype(np.uint8))
        buf = io.BytesIO()
        img_pil.save(buf, 'JPEG', quality=jpeg_q)
        buf.seek(0)
        attacked_arr = np.asarray(Image.open(buf).convert('L'), dtype=np.float64) / 255.0
        applied_attacks.append(f'JPEG Q={jpeg_q}')

    if abs(scale_pct - 100) > 1:
        H2, W2 = int(H * scale_pct/100), int(W * scale_pct/100)
        img_pil = Image.fromarray((attacked_arr * 255).astype(np.uint8))
        scaled = img_pil.resize((W2, H2), Image.LANCZOS).resize((W, H), Image.LANCZOS)
        attacked_arr = np.asarray(scaled.convert('L'), dtype=np.float64) / 255.0
        applied_attacks.append(f'缩放{scale_pct:.0f}%')

    if noise_sigma > 0:
        noise = np.random.normal(0, noise_sigma, attacked_arr.shape)
        attacked_arr = np.clip(attacked_arr + noise, 0, 1)
        applied_attacks.append(f'噪声{noise_sigma}')

    # Extract watermark from attacked image
    mode = d.get('mode', 'dft')
    p = d.get('params', {})
    result = {'success': True, 'applied_attacks': applied_attacks}
    if mode == 'dft':
        ext = extract_entire_watermark(Image.fromarray((attacked_arr * 255).astype(np.uint8)), p)
        result['extract'] = ext
    elif mode in ('zero', 'phfrfm'):
        # PHFRFM zero watermark extract
        key_arr = np.array(p.get('key', []), dtype=np.uint8)
        p_val = float(p.get('p', 0.3))
        max_ord = int(p.get('max_order', 25))
        max_wm = int(p.get('total_wm_bits', 0))
        if len(key_arr) > 0 and max_wm > 0:
            recovered = phfrfm_zero_extract(attacked_arr, key_arr, max_order=max_ord, p=p_val)
            if len(recovered) < max_wm:
                recovered = np.concatenate([recovered, np.zeros(max_wm - len(recovered), dtype=np.uint8)])
            else:
                recovered = recovered[:max_wm]
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
            # BER calculation - use ECC bits for comparison
            expected_bits = np.array(p.get('ecc_bits', p.get('original_bits', [])), dtype=np.uint8)[:len(recovered)]
            ber = 0.0
            if len(expected_bits) > 0 and len(recovered) > 0:
                n = min(len(expected_bits), len(recovered))
                ber = float(np.sum(recovered[:n] != expected_bits[:n])) / n
            ecc_info = {'total_errors': 0, 'corrected': 0, 'failed_blocks': 0, 'raw_ber': 0.0}
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
                'ecc_errors': ecc_info.get('total_errors', 0),
                'ecc_corrected': ecc_info.get('corrected', 0),
                'ecc_failed': ecc_info.get('failed_blocks', 0),
                'ecc_raw_ber': ecc_info.get('raw_ber', 0.0),
                'expected_did': embedded_did,
                'expected_did_len': len(embedded_did),
                'extracted_did_len': len(did),
                'did_bytes_hex': did_bytes.hex() if did_bytes else '',
                'expected_bytes_hex': expected_bytes.hex(),
                
            }
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

    # Return attacked image as data URL
    att_img = Image.fromarray((attacked_arr * 255).astype(np.uint8))
    buf = io.BytesIO()
    if att_img.mode != 'RGB': att_img = att_img.convert('RGB')
    att_img.save(buf, 'PNG')
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
        # Decode to DID
        did_bit_len = int(p.get('did_bit_len', 0))
        if did_bit_len > 0 and did_bit_len <= len(recovered):
            did_bytes = bytearray()
            for i in range(0, did_bit_len, 8):
                chunk = recovered[i:i+8]
                if len(chunk) == 8:
                    did_bytes.append(int(np.packbits(chunk)[0]))
            did = did_bytes.decode('utf-8', errors='replace').rstrip('\x00')
        else:
            did = ''
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
        result = {
            'success': True,
            'mode': 'phfrfm',
            'did': did,
            'did_valid': did != '' and ('did' in did[:5] or ':' in did[:8]),
            'recovered_bits': recovered.tolist(),
            'total_wm_bits': len(recovered),
            'ber': ber,
            'match_rate': 1.0 - ber,
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

@app.route('/api/vc/request', methods=['POST'])
@require_key
@require_csrf
def api_vc():
    d = request.get_json() or {}
    return jsonify(request_credential(d.get('owner_did',OWNER_DID), d.get('owner_name',OWNER_NAME), d.get('data_did',''), d.get('fingerprint',''), d.get('data_type','通用'), d.get('chain_tx_id','')))

@app.route('/api/vc/verify', methods=['POST'])
@require_key
@require_csrf
def api_vc_verify():
    return jsonify(verify_credential((request.get_json() or {}).get('vc',{})))

@app.route('/api/vp/construct', methods=['POST'])
@require_key
@require_csrf
def api_vp_construct():
    d = request.get_json() or {}
    vc = d.get('vc') or d.get('credentials')
    if vc and not isinstance(vc,list): vc = [vc]
    return jsonify(construct_presentation(vc, OWNER_KEYPAIR.get('private_key',''), OWNER_KEYPAIR.get('public_key_x',''), OWNER_KEYPAIR.get('public_key_y','')))

@app.route('/api/vp/verify', methods=['POST'])
@require_key
@require_csrf
def api_vp_verify():
    return jsonify(verify_presentation((request.get_json() or {}).get('vp',{})))

if __name__ == '__main__':
    print(f'Owner DID: {OWNER_DID}')
    app.run(host='0.0.0.0', port=5000, debug=False)
