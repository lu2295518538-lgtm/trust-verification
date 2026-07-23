"""BCH/Hamming error-correcting codes for PHFRFM watermark"""

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
    [0, 1, 1, 0],
    [0, 1, 0, 0],
    [0, 0, 1, 0],
    [0, 0, 0, 1],
], dtype=np.uint8)


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
            # s_val is the error position (1-indexed), flip that bit
            err_pos = s_val - 1  # Convert to 0-indexed
            if 0 <= err_pos < 7:
                codeword[err_pos] ^= 1
                corrected += 1
                error_locs.append((i * 7 + err_pos, 1))
                errors += 1
            else:
                # Uncorrectable
                failed += 1
            
            # Extract data bits (positions 2,4,5,6 are systematic)
            decoded[i*4:(i+1)*4] = np.array([codeword[2], codeword[4], codeword[5], codeword[6]])
    
    # Remove padding
    if pad > 0:
        decoded = decoded[:-pad]
    
    return decoded, error_locs, errors, corrected, failed


def encode_with_ecc(did_bits):
    """Full ECC pipeline: DID bits → Hamming(7,4) encode → embed bits
    
    Returns: (ecc_bits, pad, total_blocks)
    """
    return hamming_encode(np.array(did_bits, dtype=np.uint8))


def decode_with_ecc(ecc_bits, pad=0):
    """Full ECC pipeline: recovered bits → Hamming(7,4) decode → DID bits
    
    Returns: (did_bits, error_info)
        error_info: {errors, corrected, failed, error_locations, raw_ber}
    """
    recovered, locs, errs, corr, fail = hamming_decode(np.array(ecc_bits, dtype=np.uint8), pad)
    
    info = {
        'total_errors': errs,
        'corrected': corr,
        'failed_blocks': fail,
        'error_locations': locs[:10],  # First 10 error locations
        'raw_ber': float(errs + fail * 7) / len(ecc_bits) if len(ecc_bits) > 0 else 0.0,
    }
    return recovered, info
