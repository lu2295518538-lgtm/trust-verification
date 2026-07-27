"""BCH/Hamming error-correcting codes for PHFRFM watermark

With bit interleaving to spread burst errors across Hamming blocks,
preventing mis-correction when multiple errors cluster in one block.
"""

import numpy as np

# ─── Hamming(7,4) ─── corrects 1 bit error per 7-bit block

# Parity check matrix H
H = np.array([
    [1, 0, 1, 0, 1, 0, 1],
    [0, 1, 1, 0, 0, 1, 1],
    [0, 0, 0, 1, 1, 1, 1],
], dtype=np.uint8)

# Generator matrix G (4 data bits → 7 codeword bits)
G = np.array([
    [1, 1, 0, 1],
    [1, 0, 1, 1],
    [1, 0, 0, 0],
    [0, 1, 1, 1],
    [0, 1, 0, 0],
    [0, 0, 1, 0],
    [0, 0, 0, 1],
], dtype=np.uint8)

# Syndrome -> error position (0-indexed) lookup, derived from H's actual
# column values. H's columns are a PERMUTED binary set (4,2,6,1,5,3,7), so we
# cannot use the naive `err_pos = s_val - 1`. For a single-bit error at
# position p, the syndrome equals H column p, and every column is distinct,
# so this reverse-map is unique and exact.
_SYNDROME_TO_POS = {}
for _pos in range(7):
    _syn = int(H[0][_pos]) * 4 + int(H[1][_pos]) * 2 + int(H[2][_pos])
    _SYNDROME_TO_POS[_syn] = _pos


def _interleave(bits, n_cols):
    """Length-preserving column-major interleaver.

    Spreads consecutive input bits into widely-separated output positions
    so burst errors get dispersed across many Hamming blocks.

    IMPORTANT: this is a pure permutation of the input — NO padding bytes
    are appended. We enumerate the matrix cells in column-major order but
    only visit cells whose row-major index is < n, so the output length
    equals the input length and the downstream Hamming(7,4) framing never
    sees stray padding bits.
    """
    bits = np.asarray(bits, dtype=np.uint8)
    n = len(bits)
    if n == 0:
        return []
    n_rows = (n + n_cols - 1) // n_cols
    # Row-major flat index of every matrix cell, then traverse column-major
    c_idx = np.arange(n_rows * n_cols).reshape(n_rows, n_cols)
    order = c_idx.flatten(order='F')
    valid = order < n
    return bits[order[valid]].tolist()


def _deinterleave(bits, n_cols, original_len):
    """Strict inverse of _interleave.

    Reconstructs the original row-major sequence by placing each interleaved
    bit back into its source cell (identified by the same column-major
    traversal with the same < original_len filter). Length-preserving.
    """
    bits = np.asarray(bits, dtype=np.uint8)
    n = original_len
    if n == 0:
        return []
    n_rows = (n + n_cols - 1) // n_cols
    c_idx = np.arange(n_rows * n_cols).reshape(n_rows, n_cols)
    order = c_idx.flatten(order='F')
    valid = order < n
    out = np.zeros(n, dtype=np.uint8)
    # order[valid] is a permutation of 0..n-1; bits has exactly n entries
    out[order[valid]] = bits
    return out.tolist()


def hamming_encode(data_bits):
    """Encode data bits using Hamming(7,4).

    Adds padding to make length divisible by 4.
    Each 4 data bits → 7 encoded bits.

    Returns: (encoded_bits, padding_count, total_blocks)
    """
    n = len(data_bits)
    # Pad to multiple of 4
    pad = (4 - (n % 4)) % 4
    padded = np.concatenate([data_bits, np.zeros(pad, dtype=np.uint8)])

    blocks = len(padded) // 4
    encoded = np.zeros(blocks * 7, dtype=np.uint8)

    for i in range(blocks):
        data = padded[i*4:(i+1)*4]
        codeword = (G @ data) % 2
        encoded[i*7:(i+1)*7] = codeword

    return encoded, pad, blocks


def hamming_decode(encoded_bits, pad=0):
    """Decode Hamming(7,4) encoded bits.

    Corrects up to 1 bit error per 7-bit block.
    Returns: (decoded_bits, error_locations, corrected_count, failed_blocks)
    """
    errors = 0
    corrected = 0
    failed = 0
    error_locs = []

    blocks = len(encoded_bits) // 7
    decoded = np.zeros(blocks * 4, dtype=np.uint8)

    for i in range(blocks):
        codeword = encoded_bits[i*7:(i+1)*7]

        # Compute syndrome s = H · c^T (mod 2)
        syndrome = (H @ codeword) % 2

        # Convert syndrome to integer
        s_val = int(syndrome[0]*4 + syndrome[1]*2 + syndrome[2])

        if s_val == 0:
            # No error
            decoded[i*4:(i+1)*4] = np.array([codeword[2], codeword[4], codeword[5], codeword[6]])
        else:
            # Map syndrome back to the actual error position via H's columns.
            # (Naive s_val-1 is wrong here because H is column-permuted.)
            err_pos = _SYNDROME_TO_POS.get(s_val, -1)
            if 0 <= err_pos < 7:
                codeword[err_pos] ^= 1
                corrected += 1
                error_locs.append((i * 7 + err_pos, 1))
                errors += 1
            else:
                # Uncorrectable (2+ errors mapping to an invalid syndrome)
                failed += 1

            # Extract data bits (positions 2,4,5,6 are systematic)
            decoded[i*4:(i+1)*4] = np.array([codeword[2], codeword[4], codeword[5], codeword[6]])

    # Remove padding
    if pad > 0:
        decoded = decoded[:-pad]

    return decoded, error_locs, errors, corrected, failed


# Interleaving depth: use ~number of Hamming blocks as columns
# so each Hamming block gets bits from widely-separated positions
_DEFAULT_INTERLEAVE_DEPTH = 23  # ~sqrt(644/7*7), adjustable


def encode_with_ecc(did_bits, interleave_depth=_DEFAULT_INTERLEAVE_DEPTH):
    """Full ECC pipeline: DID bits → Hamming(7,4) encode → interleave → embed bits

    Interleaving spreads burst errors across Hamming blocks so that
    clustered bit errors (common in image processing) don't overwhelm
    single-block correction capability.

    Returns: (ecc_bits, pad, total_blocks)
    """
    raw_encoded, pad, blocks = hamming_encode(np.array(did_bits, dtype=np.uint8))
    # Interleave the Hamming codewords
    interleaved = _interleave(raw_encoded, interleave_depth)
    return interleaved, pad, blocks


def decode_with_ecc(ecc_bits, pad=0, interleave_depth=_DEFAULT_INTERLEAVE_DEPTH):
    """Full ECC pipeline: recovered bits → de-interleave → Hamming(7,4) decode → DID bits

    Returns: (did_bits, error_info)
        error_info: {errors, corrected, failed, error_locations, raw_ber}
    """
    # De-interleave first (spreads clustered errors apart)
    deintl = _deinterleave(ecc_bits, interleave_depth, len(ecc_bits))
    recovered, locs, errs, corr, fail = hamming_decode(np.array(deintl, dtype=np.uint8), pad)

    info = {
        'total_errors': errs,
        'corrected': corr,
        'failed_blocks': fail,
        'error_locations': locs[:10],
        'raw_ber': float(errs + fail * 7) / len(ecc_bits) if len(ecc_bits) > 0 else 0.0,
    }
    return recovered, info
