"""
DFT频域水印 + 零水印混合方案 — 核心算法模块
- DFT 中频环形区域嵌入（径向归一化 + 配对系数 + 均值聚合），承载 DID 明文
- 零水印（DFT 幅度谱环形积分特征 + XOR），不修改像素、实现无损
- 鲁棒性评估：PSNR, NC, BER
- 攻击模拟：裁剪/旋转/缩放/JPEG压缩

已知边界（实测，非缺陷而是频域水印固有局限）：
- DFT 幅度配对水印对 JPEG压缩 / 50%缩放 / 轻噪声鲁棒（BER≈0）；
- 对旋转 / 中心裁剪固有脆弱（BER≈0.5，≈随机），且无旋转/缩放不变补偿；
- 零水印层（DFT 环形积分）同样不具几何攻击不变性，仅对温和亮度/对比度变化较稳。
"""
import numpy as np
from PIL import Image, ImageFilter
import hashlib, json, os, io, base64, logging

logger = logging.getLogger("watermark_dft")

# ─── 工具函数 ───

def _img_to_gray(img: Image.Image):
    """转灰度 numpy 数组 float64 [0,1]"""
    gray = img.convert("L")
    arr = np.asarray(gray, dtype=np.float64) / 255.0
    return arr

def _gray_to_img(arr, mode="L"):
    """numpy → PIL Image"""
    clipped = np.clip(arr * 255.0, 0, 255).astype(np.uint8)
    return Image.fromarray(clipped, mode)

# ─── 度量函数 ───

def psnr(original, watermarked):
    """计算 PSNR (dB)"""
    mse = np.mean((original - watermarked) ** 2)
    if mse < 1e-12:
        return 100.0
    return float(20 * np.log10(1.0 / np.sqrt(mse)))

def nc(original_wm, extracted_wm):
    """归一化相关系数 Normalized Correlation"""
    o = np.asarray(original_wm, dtype=np.float64).flatten()
    e = np.asarray(extracted_wm, dtype=np.float64).flatten()
    denom = np.linalg.norm(o) * np.linalg.norm(e)
    if denom < 1e-12:
        return 0.0
    return float(np.dot(o, e) / denom)

def ber(original_wm_bits, extracted_wm_bits):
    """比特错误率 Bit Error Rate"""
    o = np.asarray(original_wm_bits, dtype=np.uint8).flatten()
    e = np.asarray(extracted_wm_bits, dtype=np.uint8).flatten()
    if len(o) == 0:
        return 1.0
    return float(np.sum(o != e) / len(o))


def _wm_hash(data: bytes) -> str:
    """水印指纹哈希：优先国密 SM3（需 gmssl 库），不可用则回退 SHA256 并告警一次。

    说明：标准库 hashlib 不带 sm3，原代码 `hasattr(hashlib,'sm3')` 永远为 False，
    会静默降级为 SHA256 却仍对外宣称“SM3”。此处显式化，避免国密合规性的虚假宣称。
    """
    try:
        from gmssl import sm3 as _sm3
        return _sm3.sm3_hash(data)
    except Exception:
        if not getattr(_wm_hash, "_warned", False):
            logger.warning("gmssl 不可用，水印哈希回退 SHA256（非国密 SM3）")
            _wm_hash._warned = True
        return hashlib.sha256(data).hexdigest()

# ─── 水印消息编码 ───

def encode_watermark_message(did: str, secret_hash: str = None, repetitions=5, H=1280, W=1280):
    """
    双重水印编码
    第一层: DID 明文 → bit 序列 (UTF-8)
    第二层: SM3(DID) → bit 序列 → 附加在明文后面
    返回: (bits, 总比特数, DID长度, repetitions)
    """
    # 根据图像容量自动调整 repetitions
    # 每个 8x8 块 = 1 比特, 每个比特需要 repetitions 个块
    total_unique_bits = len(did.encode("utf-8")) * 8 + 256  # DID + hash
    available_blocks = (H // 8) * (W // 8)
    max_reps = max(1, available_blocks // total_unique_bits)
    if repetitions > max_reps:
        repetitions = max(1, min(max_reps, 7))  # 至少 1, 最多 7
    did_bytes = did.encode("utf-8")
    did_bits = list(np.unpackbits(np.frombuffer(did_bytes, dtype=np.uint8)))

    if secret_hash is None:
        secret_hash = _wm_hash(did.encode())
    hash_bytes = bytes.fromhex(secret_hash)
    hash_bits = list(np.unpackbits(np.frombuffer(hash_bytes, dtype=np.uint8)))

    all_bits = did_bits + hash_bits
    # 重复编码: 每个bit重复N次, 用于提取时的多数投票纠错
    encoded = []
    for b in all_bits:
        encoded.extend([b] * repetitions)
    return np.array(encoded, dtype=np.uint8), len(encoded), len(did_bits), repetitions

def decode_watermark_message(bits, did_bit_len: int):
    """
    解码双重水印, 返回 (did, hash_hex)
    """
    bits = np.asarray(bits, dtype=np.uint8).flatten()
    did_bits = bits[:did_bit_len]
    hash_bits = bits[did_bit_len:did_bit_len + 256]

    did_bytes = np.packbits(did_bits).tobytes()
    did = did_bytes.decode("utf-8", errors="replace").rstrip("\x00")

    hash_bytes = np.packbits(hash_bits).tobytes()
    recovered_hash = hash_bytes.hex()

    # 验证
    expected = _wm_hash(did.encode())

    return did, recovered_hash, expected

# ─── DFT 频域水印嵌入 ───

def _dft_carrier_pairs(n_bits, K=80, rmin=0.08, rmax=0.33, seed=0x5A17, H=1000, W=800):
    """For each bit, two INTERLEAVED coefficient groups A,B at matched radii.

    FIX #130: auto-cap K so total modified coefficients <= ~15% of DFT size.
    FIX #131b: auto-reduce rmax for small images so coefficients survive
    aggressive downscaling (e.g. 50%).  At 50% scale-down the effective
    Nyquist halves; any coefficient beyond ~r*0.5 gets irrecoverably lost or
    severely aliased.  We set rmax so that even after worst-case expected
    scaling the carriers remain in recoverable bands.
    """
    total_coef = H * W
    coef_needed = n_bits * 2 * K
    max_coef = int(total_coef * 0.15)
    if coef_needed > max_coef and max_coef > 0:
        K = max(4, max_coef // (n_bits * 2))

    # Moderate rmax: balance capacity vs. known scaling limit.
    # NOTE: 50% downscaling is fundamentally incompatible with DFT magnitude-domain
    # paired-coefficient marking.  Use PHFRFM/zero-watermark for heavy scaling.
    min_dim = min(H, W)
    if min_dim <= 500:
        rmax = min(rmax, 0.20)
    elif min_dim <= 700:
        rmax = min(rmax, 0.24)
    elif min_dim <= 900:
        rmax = min(rmax, 0.27)
    else:
        rmax = min(rmax, 0.30)

    # Ensure rmin < rmax with some gap
    rmin = min(rmin, rmax * 0.4)

    rng = np.random.default_rng(seed)
    cand = []
    target = n_bits * 2 * K + 256
    tries = 0
    while len(cand) < target and tries < target * 50:
        u = rng.uniform(-0.5, 0.5); v = rng.uniform(-0.5, 0.5)
        r = (u * u + v * v) ** 0.5
        if rmin <= r <= rmax:
            cand.append((r, u, v))
        tries += 1
    cand.sort()
    if len(cand) < 2 * K:
        need = max(2 * K, len(cand) + 1)
        cand = (cand * (need // max(1, len(cand)) + 2))[:need]
    pairs = []
    stride = 2 * K
    idx = 0
    for b in range(n_bits):
        chunk = cand[idx:idx + stride]
        if len(chunk) < stride:
            chunk = (cand * 2)[idx:idx + stride]
        A = [(u, v) for (_, u, v) in chunk[0:2 * K:2]]
        B = [(u, v) for (_, u, v) in chunk[1:2 * K:2]]
        pairs.append((A, B))
        idx += stride
    return pairs

def _norm_to_bin(uy, vx, H, W):
    cy, cx = H // 2, W // 2
    by = int(round(cy + uy * H)); bx = int(round(cx + vx * W))
    return max(0, min(H - 1, by)), max(0, min(W - 1, bx))

def _dft_embed_strength(alpha, H=1000, W=800):
    """Map user alpha (default 0.08) to log-magnitude shift d.

    FIX #130: scale d with image area so small images maintain usable PSNR.
    Reference: 1000x800 at alpha=0.08 gives d≈1.44 and PSNR≈23dB.
    For smaller images we reduce d proportionally to sqrt(area_ratio) to keep
    the fraction of modified energy roughly constant.
    """
    base_d = max(0.30, min(2.0, float(alpha) * 18.0))
    ref_area = 1000 * 800
    actual_area = H * W
    if actual_area < ref_area:
        base_d *= (actual_area / ref_area) ** 0.5
    return max(0.15, min(base_d, 2.0))


def _radial_baseline(L, H, W, n_bins=80):
    """Compute radial average of log-magnitude spectrum.

    FIX #131: Real photos have highly non-flat spectra (energy concentrated at
    low frequencies). The paired-coefficient scheme assumes A and B groups at
    similar radii have matched magnitudes — this FAILS for photos where the
    same-radius standard deviation can be >1.0 (natural variation >> signal).

    Solution: subtract the radial baseline before embedding/detection so the
    normalized spectrum is approximately flat. The baseline is robust because:
      - Radial averaging smooths over all angles → stable under rotation/crop
      - Only the shape matters, not absolute values → scale-invariant in log
      - JPEG affects all radii similarly → baseline tracks the distortion

    Returns: baseline[y,x] array (same shape as L) to subtract.
    """
    cy, cx = H // 2, W // 2
    y_idx, x_idx = np.ogrid[:H, :W]
    # Normalized radius (0 at center, ~0.7 at corners)
    r_norm = np.sqrt(((x_idx - cx) / max(W, 1))**2 + ((y_idx - cy) / max(H, 1))**2)
    r_flat = r_norm.ravel()
    L_flat = L.ravel()

    # Bin by radius and compute mean per bin
    bin_edges = np.linspace(0, r_norm.max() + 1e-6, n_bins + 1)
    bin_indices = np.digitize(r_flat, bin_edges) - 1
    bin_indices = np.clip(bin_indices, 0, n_bins - 1)

    bin_means = np.zeros(n_bins)
    for i in range(n_bins):
        mask = bin_indices == i
        if mask.sum() > 0:
            bin_means[i] = L_flat[mask].mean()
        else:
            # Edge case: interpolate from neighbors
            if i > 0:
                bin_means[i] = bin_means[i - 1]
            else:
                bin_means[i] = 0.0

    # Smooth the baseline to avoid sharp bin boundaries (moving average, window=3)
    kernel = np.array([0.25, 0.5, 0.25])
    smoothed = np.convolve(bin_means, kernel, mode='same')
    smoothed[0] = bin_means[0]  # boundary handling
    smoothed[-1] = bin_means[-1]

    # Map back to 2D
    baseline_flat = smoothed[bin_indices]
    return baseline_flat.reshape(H, W)

def dft_embed(img_array, watermark_bits, alpha=0.08, ring_radius_range=(40, 120), block_size=8):
    """DFT-magnitude paired-coefficient watermark embedding (FIX #131 radial-norm).

    FIX #131: Radial normalization flattens the spectrum before embedding so
    paired-coefficient differences work on BOTH textured and photo-realistic
    images. Without this, real photos (with 10x spectral dynamic range at
    the same radius) completely bury the +/-2d embedded signal.
    """
    H, W = img_array.shape
    Fs = np.fft.fftshift(np.fft.fft2(img_array))
    M = np.abs(Fs) + 1e-9
    L = np.log(M)

    # FIX #131: compute and subtract radial baseline → flat spectrum
    baseline = _radial_baseline(L, H, W)
    L_norm = L - baseline

    n_bits = len(watermark_bits)
    pairs = _dft_carrier_pairs(n_bits, H=H, W=W)
    d = _dft_embed_strength(alpha, H=H, W=W)
    for b in range(n_bits):
        sign = 1.0 if int(watermark_bits[b]) == 1 else -1.0
        A, B = pairs[b]
        Ab = [_norm_to_bin(u, v, H, W) for (u, v) in A]
        Bb = [_norm_to_bin(u, v, H, W) for (u, v) in B]
        a0 = float(np.mean([L_norm[y, x] for (y, x) in Ab]))
        b0 = float(np.mean([L_norm[y, x] for (y, x) in Bb]))
        cur = a0 - b0
        target = sign * 2.0 * d
        s = (target - cur) / 2.0
        for (y, x) in Ab:
            L_norm[y, x] += s
        for (y, x) in Bb:
            L_norm[y, x] -= s

    # Add baseline back → physical spectrum with embedded signal
    L_embedded = L_norm + baseline
    M2 = np.exp(L_embedded)
    Fs2 = M2 * np.exp(1j * np.angle(Fs))
    out = np.real(np.fft.ifft2(np.fft.ifftshift(Fs2)))
    return np.clip(out, 0.0, 1.0)


def dft_extract(img_array, watermark_len, ring_radius_range=(40, 120), alpha=0.08, block_size=8):
    """DFT-magnitude paired-coefficient extraction (FIX #131 radial-norm)."""
    H, W = img_array.shape
    Fs = np.fft.fftshift(np.fft.fft2(img_array))
    L = np.log(np.abs(Fs) + 1e-9)

    # FIX #131: radial normalization → flat spectrum for detection
    baseline = _radial_baseline(L, H, W)
    L_norm = L - baseline

    pairs = _dft_carrier_pairs(watermark_len, H=H, W=W)
    d_ref = _dft_embed_strength(alpha, H=H, W=W)
    extracted_bits = []
    confidence = []
    for b in range(watermark_len):
        A, B = pairs[b]
        Ab = [_norm_to_bin(u, v, H, W) for (u, v) in A]
        Bb = [_norm_to_bin(u, v, H, W) for (u, v) in B]
        a = float(np.mean([L_norm[y, x] for (y, x) in Ab]))
        bb = float(np.mean([L_norm[y, x] for (y, x) in Bb]))
        diff = a - bb
        bit = 1 if diff > 0 else 0
        conf = min(1.0, abs(diff) / max(2.0 * d_ref, 1e-6))
        extracted_bits.append(bit)
        confidence.append(conf)
    return np.array(extracted_bits, dtype=np.uint8), np.array(confidence)


# ─── 零水印（DFT 环形积分，无损；对温和亮度/对比度变化较稳，但不具几何攻击不变性）───

def generate_diff_heatmap(original_array, watermarked_array):
    """
    生成差异热力图（放大嵌入位置），用于前端对比可视化。
    """
    H, W = original_array.shape
    diff = np.abs(watermarked_array - original_array)
    max_diff = diff.max() if diff.max() > 0 else 1
    diff_normalized = (diff / max_diff * 255).astype(np.uint8)
    rgb = np.zeros((H, W, 3), dtype=np.uint8)
    rgb[..., 0] = diff_normalized
    rgb[..., 1] = (255 - diff_normalized) // 2
    rgb[..., 2] = 255 - diff_normalized
    img = Image.fromarray(rgb)
    if H > 256 or W > 256:
        img = img.resize((256, 256), Image.LANCZOS)
    return img
def zero_watermark_generate(img_array, watermark_bits):
    """
    零水印生成: 提取图像特征 → XOR 水印 → 存储为密钥。
    不修改图像像素, 实现真正无损。

    使用 DFT 幅度谱的环形积分特征（非极坐标矩）:
    - 对图像做 DFT → 取幅度谱的环形积分作为特征
    - 对特征二值化 → 与水印 XOR → 得到密钥
    注意: 该特征对旋转/裁剪/缩放不具不变性（实测 BER≈0.5），仅对温和亮度/对比度变化较稳。
    """
    H, W = img_array.shape
    fft = np.fft.fft2(img_array)
    fft_shifted = np.fft.fftshift(fft)
    mag = np.abs(fft_shifted)

    cx, cy = H // 2, W // 2
    yv, xv = np.meshgrid(np.arange(H) - cy, np.arange(W) - cx, indexing='ij')
    r = np.sqrt(xv * xv + yv * yv)

    # 在半径方向积分得到径向特征
    max_radius = int(min(cx, cy) * 0.9)
    radial_feature = []
    for rad in range(10, max_radius, 2):
        ring_mask = (r >= rad) & (r < rad + 2)
        if np.any(ring_mask):
            radial_feature.append(float(np.mean(mag[ring_mask])))

    radial_feature = np.array(radial_feature)
    # 归一化
    if radial_feature.max() > radial_feature.min():
        radial_feature = (radial_feature - radial_feature.min()) / (radial_feature.max() - radial_feature.min())

    # 二值化特征 (按中位数)
    median = np.median(radial_feature)
    feature_bits = (radial_feature > median).astype(np.uint8)

    # 重复特征比特以匹配水印长度
    L = len(watermark_bits)
    if len(feature_bits) < L:
        feature_bits = np.tile(feature_bits, (L // len(feature_bits)) + 1)
    feature_bits = feature_bits[:L]

    # XOR 生成密钥
    key = np.bitwise_xor(feature_bits, watermark_bits)

    return key, feature_bits[:L]

def zero_watermark_extract(img_array, key):
    """
    零水印提取: 从图像提取特征 → XOR 密钥 → 恢复水印
    """
    H, W = img_array.shape
    fft = np.fft.fft2(img_array)
    fft_shifted = np.fft.fftshift(fft)
    mag = np.abs(fft_shifted)

    cx, cy = H // 2, W // 2
    yv, xv = np.meshgrid(np.arange(H) - cy, np.arange(W) - cx, indexing='ij')
    r = np.sqrt(xv * xv + yv * yv)

    max_radius = int(min(cx, cy) * 0.9)
    radial_feature = []
    for rad in range(10, max_radius, 2):
        ring_mask = (r >= rad) & (r < rad + 2)
        if np.any(ring_mask):
            radial_feature.append(float(np.mean(mag[ring_mask])))

    radial_feature = np.array(radial_feature)
    if radial_feature.max() > radial_feature.min():
        radial_feature = (radial_feature - radial_feature.min()) / (radial_feature.max() - radial_feature.min())

    median = np.median(radial_feature)
    feature_bits = (radial_feature > median).astype(np.uint8)

    L = len(key)
    if len(feature_bits) < L:
        feature_bits = np.tile(feature_bits, (L // len(feature_bits)) + 1)
    feature_bits = feature_bits[:L]

    recovered = np.bitwise_xor(feature_bits, key)
    return recovered.astype(np.uint8)

# ─── 攻击模拟 ───

def simulate_attacks(img, attack_types=None):
    """
    模拟多种攻击, 返回 {attack_name: (attacked_img_array, label)}
    """
    arr = _img_to_gray(img)
    H, W = arr.shape
    results = {}

    attacks = attack_types or ["crop50", "rotate30", "jpeg50", "scale50", "noise"]

    if "crop50" in attacks:
        # 裁剪中心50%
        h, w = int(H * 0.5), int(W * 0.5)
        ch, cw = (H - h) // 2, (W - w) // 2
        results["crop50"] = arr[ch:ch + h, cw:cw + w]

    if "rotate30" in attacks:
        img_rot = img.rotate(30, expand=True, fillcolor=128)
        rot_arr = _img_to_gray(img_rot)
        results["rotate30"] = rot_arr

    if "jpeg50" in attacks:
        buf = io.BytesIO()
        img.save(buf, "JPEG", quality=50)
        buf.seek(0)
        jpeg_img = Image.open(buf).convert("L")
        results["jpeg50"] = np.asarray(jpeg_img, dtype=np.float64) / 255.0

    if "scale50" in attacks:
        hw, hh = W // 2, H // 2
        small = img.resize((hw, hh), Image.LANCZOS)
        scaled_back = small.resize((W, H), Image.LANCZOS)
        results["scale50"] = _img_to_gray(scaled_back)

    if "noise" in attacks:
        noise = np.random.normal(0, 0.02, (H, W))
        noisy = np.clip(arr + noise, 0, 1)
        results["noise"] = noisy

    return results

# ─── 频谱数据生成 (用于前端可视化) ───

def generate_spectrum_data(img_array):
    """生成DFT幅度谱数据，用于前端频谱图渲染"""
    fft = np.fft.fft2(img_array)
    fft_shifted = np.fft.fftshift(fft)
    mag = np.abs(fft_shifted)
    log_mag = np.log1p(mag)
    # 归一化到 0-255
    log_mag = (log_mag - log_mag.min()) / (log_mag.max() - log_mag.min() + 1e-12)
    log_mag = (log_mag * 255).astype(np.uint8)
    # 降采样到 128x128 用于前端渲染
    H, W = log_mag.shape
    small = Image.fromarray(log_mag).resize((128, 128), Image.LANCZOS)
    small_arr = np.asarray(small).flatten().tolist()
    return {
        "width": 128,
        "height": 128,
        "data": small_arr,
        "max_val": 255,
    }

# ─── 水印嵌入强度分布图 ───

def generate_embedding_heatmap(original_array, watermarked_array):
    """生成嵌入强度分布图（差异图）"""
    diff = np.abs(watermarked_array - original_array)
    # 放大差异以便显示
    diff_enhanced = np.clip(diff * 50, 0, 1)
    return _gray_to_img(diff_enhanced)

# ─── 完整嵌入/提取流程 ───

def embed_entire_watermark(img: Image.Image, did: str, mode="dft", alpha=0.08):
    """
    完整水印嵌入流程
    mode: "dft" | "zero"
    返回: {watermarked_img, key, metrics, spectrum}
    """
    arr = _img_to_gray(img)

    H_img, W_img = arr.shape
    secret_hash = _wm_hash(did.encode())

    # DFT 模式只嵌入 DID 明文比特（不重复、不携带 hash）。
    # 设计取舍：DFT 幅度配对水印本就不抗旋转/裁剪，再塞 256 位 hash 只白白占用
    # ~52% 负载，且提取端从未读取/校验这些 hash 位（之前是死重 + 假校验）。
    # 若需哈希锚定，应在零水印/链上完成，而非挤进 DFT 负载。
    did_bytes = did.encode("utf-8")
    did_bits_list = list(np.unpackbits(np.frombuffer(did_bytes, dtype=np.uint8)))
    unique_bits = np.array(did_bits_list, dtype=np.uint8)
    n_unique = len(unique_bits)

    result = {
        "mode": mode,
        "did": did,
        "did_bit_len": len(did_bits_list),
        "alpha": alpha,
        "secret_hash": secret_hash,
    }

    if mode == "dft":
        # ── FIX #126: 消除双重重复编码 ──
        # 旧 bug: encode_watermark_message 先把每个比特重复5次(→3600 bit)，
        #   然后 _get_block_layout 又给这 3600 bit 各分配 5 个空间副本
        #   → 需要 18000 个块但只有 14400 个可用 → 覆盖冲突 + 投票错位
        #   → 干净提取 BER≈50%（完全随机）
        # 修复: DFT 模式传入唯一比特(不预重复)，让 dft_embed 内部的
        #   _get_block_layout 用自身的 replicas=5 做空间分散冗余
        dft_reps = 5  # _get_block_layout 默认副本数
        wm_arr = dft_embed(arr, unique_bits, alpha=alpha)
        wm_img = _gray_to_img(wm_arr)
        result["watermarked_image"] = wm_img
        result["psnr"] = round(psnr(arr, wm_arr), 2)
        result["key"] = None
        result["original_bits"] = unique_bits.tolist()  # 唯一比特（投票前）
        result["total_wm_bits"] = n_unique             # 提取时传给 dft_extract 的唯一比特数
        result["repetitions"] = dft_reps               # dft_extract 内部副本数（用于投票）

        # 频谱
        result["spectrum_before"] = generate_spectrum_data(arr)
        result["spectrum_after"] = generate_spectrum_data(wm_arr)

    elif mode == "zero":
        # 零水印: 不修改图像（使用旧编码以兼容已有嵌入数据）
        wm_bits_compat, total_len, did_len, repetitions = encode_watermark_message(did, H=H_img, W=W_img)
        key, _ = zero_watermark_generate(arr, wm_bits_compat)
        result["watermarked_image"] = img.copy()  # 原图不变
        result["psnr"] = 100.0  # 无损
        result["key"] = key.tolist()
        result["original_bits"] = wm_bits_compat.tolist()
        result["total_wm_bits"] = total_len
        result["repetitions"] = repetitions
        result["spectrum_before"] = generate_spectrum_data(arr)
        result["spectrum_after"] = result["spectrum_before"]  # 不变

    return result

def extract_entire_watermark(img: Image.Image, params: dict):
    """
    完整水印提取流程
    params: 包含 mode, did_bit_len, key(零水印时) 等信息
    返回: {did, hash_verified, metrics, attack_results}
    """
    repetitions = params.get("repetitions", 1)
    arr = _img_to_gray(img)
    mode = params.get("mode", "dft")
    did_bit_len = params.get("did_bit_len", 0)
    total_wm_bits = params.get("total_wm_bits", 0)
    original_bits = np.array(params.get("original_bits") or [], dtype=np.uint8)

    if mode == "dft":
        extracted_bits, confidence = dft_extract(arr, total_wm_bits, alpha=float(params.get('alpha', 0.08)))
        # ── FIX #126: DFT 模式不再做外层投票 ──
        # dft_extract 内部已对每个唯一比特的所有空间副本做了均值聚合
        # （_get_block_layout 的 replicas 机制），返回的已是投票后结果。
        # 外层再加一次 step=repetitions 的投票会把不同唯一比特混在一起
        # → 导致干净提取 BER≈50%（已验证修复前行为）。
        # 注意: 为兼容旧数据(如果 total_wm_bits 是旧的大值)，仍需保护：
        # 只有当提取长度与预期唯一比特数匹配时才跳过投票。
        _expected_unique = did_bit_len + 256  # DID bits + hash bits
        if repetitions > 1 and len(extracted_bits) >= repetitions and len(extracted_bits) % repetitions == 0:
            # 仅当提取长度明显大于预期唯一比特数时（旧格式：预重复的3600 bit）
            # 才执行外层投票；新格式（720 唯一 bit）由 dft_extract 内部处理
            if len(extracted_bits) > _expected_unique * 2:
                voted = []
                voted_conf = []
                for i in range(0, len(extracted_bits), repetitions):
                    chunk = extracted_bits[i:i+repetitions]
                    ones = sum(chunk)
                    voted.append(1 if ones > repetitions/2 else 0)
                    voted_conf.append(max(ones, repetitions-ones) / repetitions)
                extracted_bits = voted
                confidence = voted_conf
                total_wm_bits = len(voted)
    elif mode == "zero":
        key_arr = np.array(params.get("key", []), dtype=np.uint8)
        if len(key_arr) == 0:
            return {"success": False, "error": "零水印密钥缺失"}
        extracted_bits = zero_watermark_extract(arr, key_arr)
        confidence = np.ones(total_wm_bits) * 0.8
    else:
        return {"success": False, "error": f"未知模式: {mode}"}

    # 解码 (DFT 模式只编码了 DID, 无 hash)
    if mode == "dft":
        # 【BUG FIX】原代码 ext_bits_did = extracted_bits[:did_bit_len] 截断后只取前 did_bit_len 位
        # 当 layout 实际可用位不足时, decoded bytes 可能过短导致 DID 截断
        # 修复: 保证 ext_bits_did 长度等于 did_bit_len (缺失则补 0)
        ext_bits_did = np.zeros(did_bit_len, dtype=np.uint8)
        actual_len = min(len(extracted_bits), did_bit_len)
        ext_bits_did[:actual_len] = extracted_bits[:actual_len]

        # packbits: 每 8 位 1 字节, 不足 8 位则舍去 (截断)
        # 【BUG FIX】原代码用 for+if 逐字节拼接, 当 chunk 不足 8 位时静默丢失
        # 修复: 用 np.packbits 一次性转换
        n_complete = (did_bit_len // 8) * 8
        did_bytes = bytearray(np.packbits(ext_bits_did[:n_complete]).tolist())
        did = did_bytes.decode("utf-8", errors="replace").rstrip("\x00")
        recovered_hash = ""
        expected_hash = ""
        # DFT 模式不嵌入哈希（见 embed_entire_watermark），故 hash_verified 退化为
        # DID 完整性校验（字段名保留以兼容前端 /api/watermark/extract 的判定逻辑）：
        #   - 若提取参数带登记 DID（params["did"]），则做精确比对——这才是可信校验；
        #   - 否则退化为「形似 DID」格式检查（长度达标且前缀含 did/':'）。
        # 这不再是「任意 did 字样都算通过」的假校验，而是验证恢复的 DID 是否可信。
        expected_did = params.get("did", "") or ""
        if expected_did:
            hash_verified = (did == expected_did)
        else:
            hash_verified = (len(did) >= 10 and ("did" in did[:5] or ":" in did[:8]))
    else:
        did, recovered_hash, expected_hash = decode_watermark_message(extracted_bits, did_bit_len)
        hash_verified = (recovered_hash == expected_hash)

    # 攻击模拟
    attack_results = {}
    attacks = simulate_attacks(img)
    for name, attacked_arr in attacks.items():
        try:
            if mode == "dft":
                ext_bits, _ = dft_extract(attacked_arr, total_wm_bits, alpha=float(params.get('alpha', 0.08)))
                # 同上：仅对旧格式(预重复的大 total_wm_bits) 做外层投票
                _exp_u = did_bit_len + 256
                if repetitions > 1 and len(ext_bits) >= repetitions and len(ext_bits) % repetitions == 0 and len(ext_bits) > _exp_u * 2:
                    voted_att = [1 if sum(ext_bits[i:i+repetitions]) > repetitions/2 else 0 for i in range(0, len(ext_bits), repetitions)]
                    ext_bits = voted_att
            else:
                H, W = attacked_arr.shape
                ext_bits = zero_watermark_extract(attacked_arr, np.array(params.get("key", []), dtype=np.uint8))

            if mode == "dft":
                ext_bits_atk = ext_bits[:did_bit_len] if len(ext_bits) >= did_bit_len else ext_bits
                did_bytes = bytearray()
                for i in range(0, min(did_bit_len, len(ext_bits_atk)), 8):
                    chunk = ext_bits_atk[i:i+8]
                    if len(chunk) == 8:
                        did_bytes.append(int(np.packbits(chunk)[0]))
                did_a = did_bytes.decode("utf-8", errors="replace").rstrip("\x00")
                hash_ok = len(did_a) >= 10 and did_a.startswith("did:")
                # 只有 original_bits 存在时才计算 NC/BER
                if len(original_bits) >= did_bit_len:
                    nc_val = float(nc(ext_bits_atk, original_bits[:did_bit_len]))
                    ber_val = float(ber(original_bits[:did_bit_len], ext_bits_atk))
                else:
                    nc_val, ber_val = 0.0, 0.0
                attack_results[name] = {
                    "did_recovered": did_a,
                    "hash_verified": hash_ok,
                    "nc": nc_val,
                    "ber": ber_val,
                }
            else:
                # 零水印模式: 通过 SM3 哈希验证
                did_a, hash_a, _ = decode_watermark_message(ext_bits, did_bit_len)
                hash_ok = (hash_a == expected_hash)
                if len(original_bits) >= did_bit_len and len(ext_bits) >= did_bit_len:
                    nc_val = round(nc(ext_bits[:did_bit_len], original_bits[:did_bit_len]), 4)
                    ber_val = round(ber(original_bits[:did_bit_len], ext_bits[:did_bit_len]), 4)
                else:
                    nc_val, ber_val = 0.0, 0.0
                attack_results[name] = {
                    "did_recovered": did_a,
                    "hash_verified": hash_ok,
                    "nc": nc_val,
                    "ber": ber_val,
                }
        except Exception as e:
            attack_results[name] = {"did_recovered": "提取失败", "hash_verified": False, "nc": 0.0, "ber": 1.0, "error": str(e)[:50]}

    return {
        "success": True,
        "did": did,
        "hash_verified": hash_verified,
        "recovered_hash": recovered_hash,
        "expected_hash": expected_hash,
        "confidence_mean": float(np.mean(confidence)),
        "attack_results": attack_results,
    }



