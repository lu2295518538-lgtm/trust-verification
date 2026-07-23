#!/usr/bin/env python3
"""PHFRFM 极谐波分数傅里叶矩零水印核心算法

Reference: "极谐波分数傅里叶矩及其零水印算法应用"
Key concepts:
- Polar Harmonic Fractional Fourier Moments (PHFRFM)
- Fractional order p controls radial basis decay
- Zero watermark: XOR(feature_bits, DID_bits) → no pixel modification
"""

import numpy as np
from scipy.special import eval_genlaguerre

def _normalize_to_disk(image):
    """
    Normalize image to unit disk (radius ≤ 1).
    Returns: (norm_image, H, W) where norm_image is defined on r ∈ [0, 1]
    """
    H, W = image.shape
    cx, cy = W / 2.0, H / 2.0
    radius = min(cx, cy) * 0.95  # 5% margin

    # Create polar grid
    yv, xv = np.meshgrid(np.arange(H), np.arange(W), indexing='ij')
    r = np.sqrt((xv - cx)**2 + (yv - cy)**2) / radius

    # Mask: inside unit circle + valid coordinates
    mask = (r <= 1.0)
    if not np.any(mask):
        return None, None, None, None

    theta = np.arctan2(yv - cy, xv - cx)

    return r, theta, mask, (H, W, radius, cx, cy)

def _phfrfm_radial(r, n, p):
    """
    PHFRFM radial basis function.
    R_n(r, p) = exp(-r²/2) * r^|2n| * L_n^{(|2n|)}(r², p)

    Where L_n^{(α)}(x, p) is the generalized Laguerre polynomial evaluated
    at scaled argument with fractional modulation.
    """
    # Prevent r=0 issues
    r_safe = np.maximum(r, 1e-10)

    # Radial part: exp(-r²/2) * r^(2n) with fractional modulation
    radial = np.exp(-r_safe**2 / 2.0) * (r_safe**(2 * abs(n)))

    # Generalized Laguerre polynomial: L_n^(|2n|)(r²)
    # Scipy's eval_genlaguerre(n, alpha, x)
    alpha = 2 * abs(n)
    x = r_safe**2

    # Apply fractional modulation via parameter p
    # p controls the effective argument scaling
    x_scaled = x ** p * (1 + p * (1 - x))

    laguerre = eval_genlaguerre(n, alpha, x_scaled)

    return radial * laguerre

def compute_phfrfm_moments(image, max_order=25, p=0.3):
    """
    Compute PHFRFM moments for an image.

    Args:
        image: 2D numpy array (grayscale, float64, [0,1])
        max_order: maximum radial order (paper uses 25)
        p: fractional order parameter

    Returns:
        moments: dict mapping (n, m) → complex moment value
        num_moments: total number of unique moments
    """
    r, theta, mask, params = _normalize_to_disk(image)
    if r is None:
        return {}, 0

    H, W, radius, cx, cy = params
    dr = 1.0 / min(H, W) * 2  # radial step
    dtheta = 2 * np.pi / 180   # angular step (~2°)

    # Pre-compute radial functions for each order n
    # to avoid redundant calculations
    radial_cache = {}
    for n in range(max_order + 1):
        radial_cache[n] = _phfrfm_radial(r, n, p)
        radial_cache[n][~mask] = 0.0

    moments = {}
    num_moments = 0

    for n in range(max_order + 1):
        R_n = radial_cache[n]
        # For each n, m runs from -n to n (if using, just abs(m) for symmetric)
        for abs_m in range(n + 1):
            m = abs_m if abs_m % 2 == 0 else -abs_m

            if m >= 0:
                # Real part (cosine)
                kernel_r = R_n * np.cos(m * theta) * r
            else:
                # Imaginary part (sine)
                kernel_r = R_n * np.sin(abs(m) * theta) * r

            kernel_r[~mask] = 0.0

            # Moment = ∫∫ f(r,θ) * kernel * r * dr * dθ
            k_masked = kernel_r[mask]
            i_masked = image[mask]
            moment = np.sum(k_masked * i_masked) * dr * dtheta

            # Store magnitude (rotation invariant)
            moments[(n, m)] = abs(moment)
            num_moments += 1

    return moments, num_moments

def phfrfm_zero_generate(image, did_bits, max_order=25, p=0.3):
    """
    Generate PHFRFM zero watermark key.

    Steps:
    1. Compute PHFRFM moments
    2. Sort moments by magnitude (most significant first)
    3. Take enough coefficients to match watermark length
    4. Binarize using median threshold
    5. XOR with DID bits → key

    Returns: (key, feature_bits)
    """
    moments, num_moments = compute_phfrfm_moments(image, max_order, p)
    if not moments:
        return np.zeros(1, dtype=np.uint8), np.zeros(1, dtype=np.uint8)

    # Sort moments by magnitude (descending) - take most significant
    sorted_moments = sorted(moments.items(), key=lambda x: x[1], reverse=True)
    magnitudes = np.array([m[1] for m in sorted_moments], dtype=np.float64)

    if len(magnitudes) < 2:
        return np.zeros(1, dtype=np.uint8), np.zeros(1, dtype=np.uint8)

    # Normalize
    m_min, m_max = magnitudes.min(), magnitudes.max()
    if m_max > m_min:
        magnitudes = (magnitudes - m_min) / (m_max - m_min)

    # Need at least len(did_bits) coefficients
    n_bits = len(did_bits)
    n_available = len(magnitudes)
    n_to_use = min(n_bits, n_available)

    # Binarize: use local medians for robustness
    window = min(7, n_to_use // 4) if n_to_use > 7 else 1
    feature_bits = np.zeros(n_to_use, dtype=np.uint8)
    for i in range(n_to_use):
        local_start = max(0, i - window)
        local_end = min(n_to_use, i + window + 1)
        local_median = np.median(magnitudes[local_start:local_end])
        feature_bits[i] = 1 if magnitudes[i] > local_median else 0

    # Pad/trim to match DID bits length
    if n_to_use < n_bits:
        feature_bits = np.tile(feature_bits, (n_bits // n_to_use) + 1)[:n_bits]
    else:
        feature_bits = feature_bits[:n_bits]

    # XOR
    key = np.bitwise_xor(feature_bits, did_bits)
    return key.astype(np.uint8), feature_bits.astype(np.uint8)

def phfrfm_zero_extract(image, key, max_order=25, p=0.3):
    """
    Extract DID from zero watermark key.
    Inverse of phfrfm_zero_generate.
    """
    moments, num_moments = compute_phfrfm_moments(image, max_order, p)
    if not moments:
        return np.zeros(len(key), dtype=np.uint8)

    sorted_moments = sorted(moments.items(), key=lambda x: x[1], reverse=True)
    magnitudes = np.array([m[1] for m in sorted_moments], dtype=np.float64)

    if len(magnitudes) < 2:
        return np.zeros(len(key), dtype=np.uint8)

    m_min, m_max = magnitudes.min(), magnitudes.max()
    if m_max > m_min:
        magnitudes = (magnitudes - m_min) / (m_max - m_min)

    n_bits = len(key)
    n_available = len(magnitudes)
    n_to_use = min(n_bits, n_available)

    window = min(7, n_to_use // 4) if n_to_use > 7 else 1
    feature_bits = np.zeros(n_to_use, dtype=np.uint8)
    for i in range(n_to_use):
        local_start = max(0, i - window)
        local_end = min(n_to_use, i + window + 1)
        local_median = np.median(magnitudes[local_start:local_end])
        feature_bits[i] = 1 if magnitudes[i] > local_median else 0

    if n_to_use < n_bits:
        feature_bits = np.tile(feature_bits, (n_bits // n_to_use) + 1)[:n_bits]
    else:
        feature_bits = feature_bits[:n_bits]

    recovered = np.bitwise_xor(feature_bits, key)
    return recovered.astype(np.uint8)
