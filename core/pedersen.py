"""
Pedersen 承诺：C = fp·G + nonce·H（secp256k1 纯 Python）
"""
import hashlib
import os

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

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
        lam = (3 * x1 * x1 + A) * _mod_inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * _mod_inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)

def _point_mul(k, point):
    if k % N == 0 or point is None: return None
    result, addend = None, point
    while k:
        if k & 1: result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result

def _derive_h():
    h = hashlib.sha256(b"Pedersen H point for Livestock Trust System").digest()
    x = int.from_bytes(h, 'big') % P
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if (y * y) % P != y_sq: y = P - y
    return (x, y)

G = (Gx, Gy)
H = _derive_h()

def commit(fp_hex: str, nonce: int = None) -> dict:
    if nonce is None:
        nonce = int.from_bytes(os.urandom(32), 'big') % N
    fp_scalar = int(fp_hex, 16) % N
    c = _point_add(_point_mul(fp_scalar, G), _point_mul(nonce, H))
    if c is None: raise ValueError("承诺计算失败")
    return {
        "commitment": f"{c[0]:064x}{c[1]:064x}",
        "commitment_x": f"{c[0]:064x}",
        "commitment_y": f"{c[1]:064x}",
        "nonce": nonce,
        "nonce_hex": f"{nonce:064x}",
        "fp_hex": fp_hex,
    }

def verify_commitment(fp_hex: str, nonce: int, commitment_hex: str) -> bool:
    return commit(fp_hex, nonce)["commitment"] == commitment_hex
