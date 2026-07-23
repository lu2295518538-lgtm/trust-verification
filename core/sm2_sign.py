"""
SM2 国密数字签名（GB/T 32918-2016，sm2p256v1 纯 Python）
"""
import hashlib
import os

P_SM2 = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
A_SM2 = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
B_SM2 = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
N_SM2 = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx_SM2 = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy_SM2 = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
DEFAULT_UID = b"1234567812345678"

def _mod_inv(a, p):
    if a == 0: return 0
    lm, hm, low, high = 1, 0, a % p, p
    while low > 1:
        ratio = high // low
        nm, new = hm - lm * ratio, high - low * ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % p

def _point_add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1; x2, y2 = p2
    if x1 == x2 and y1 != y2: return None
    if x1 == x2:
        lam = (3 * x1 * x1 + A_SM2) * _mod_inv(2 * y1, P_SM2) % P_SM2
    else:
        lam = (y2 - y1) * _mod_inv(x2 - x1, P_SM2) % P_SM2
    x3 = (lam * lam - x1 - x2) % P_SM2
    y3 = (lam * (x1 - x3) - y1) % P_SM2
    return (x3, y3)

def _point_mul(k, point):
    if k % N_SM2 == 0 or point is None: return None
    result, addend = None, point
    while k:
        if k & 1: result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result

def _compute_za(pub_x, pub_y, uid=DEFAULT_UID):
    entla = (len(uid) * 8).to_bytes(2, 'big')
    return hashlib.sha256(entla + uid +
        A_SM2.to_bytes(32,'big') + B_SM2.to_bytes(32,'big') +
        Gx_SM2.to_bytes(32,'big') + Gy_SM2.to_bytes(32,'big') +
        pub_x.to_bytes(32,'big') + pub_y.to_bytes(32,'big')).digest()

def generate_keypair() -> dict:
    d = int.from_bytes(os.urandom(32), 'big') % (N_SM2 - 1) + 1
    pub = _point_mul(d, (Gx_SM2, Gy_SM2))
    return {
        "private_key": f"{d:064x}",
        "public_key": f"{pub[0]:064x}{pub[1]:064x}",
        "public_key_x": f"{pub[0]:064x}",
        "public_key_y": f"{pub[1]:064x}",
    }

def sign(message: bytes, private_key_hex: str, uid=DEFAULT_UID) -> dict:
    d = int(private_key_hex, 16)
    pub = _point_mul(d, (Gx_SM2, Gy_SM2))
    za = _compute_za(pub[0], pub[1], uid)
    while True:
        k = int.from_bytes(os.urandom(32), 'big') % (N_SM2 - 1) + 1
        kg = _point_mul(k, (Gx_SM2, Gy_SM2))
        if kg is None: continue
        e = int.from_bytes(hashlib.sha256(za + message).digest(), 'big')
        r = (e + kg[0]) % N_SM2
        if r == 0 or r + k == N_SM2: continue
        s = (_mod_inv(1 + d, N_SM2) * (k - r * d)) % N_SM2
        if s == 0: continue
        break
    return {"r": f"{r:064x}", "s": f"{s:064x}", "signature": f"{r:064x}{s:064x}"}

def verify(message: bytes, r_hex: str, s_hex: str,
           pub_x_hex: str, pub_y_hex: str, uid=DEFAULT_UID) -> bool:
    r, s = int(r_hex, 16), int(s_hex, 16)
    if r <= 0 or r >= N_SM2 or s <= 0 or s >= N_SM2: return False
    pub_x, pub_y = int(pub_x_hex, 16), int(pub_y_hex, 16)
    left = (pub_y * pub_y) % P_SM2
    right = (pow(pub_x, 3, P_SM2) + A_SM2 * pub_x + B_SM2) % P_SM2
    if left != right: return False
    za = _compute_za(pub_x, pub_y, uid)
    e = int.from_bytes(hashlib.sha256(za + message).digest(), 'big')
    t = (r + s) % N_SM2
    if t == 0: return False
    point = _point_add(_point_mul(s, (Gx_SM2, Gy_SM2)), _point_mul(t, (pub_x, pub_y)))
    if point is None: return False
    return (e + point[0]) % N_SM2 == r

def sign_string(message: str, private_key_hex: str) -> dict:
    return sign(message.encode('utf-8'), private_key_hex)
