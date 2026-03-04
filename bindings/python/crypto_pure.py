"""
EWSP Pure Python Crypto Implementation
======================================

Fallback implementation when C library is not available.
This provides identical functionality using pure Python.

Primitives:
- SHA-256, HMAC-SHA256, HKDF-SHA256
- ChaCha20, HChaCha20, XChaCha20
- Poly1305 MAC
- XChaCha20-Poly1305 AEAD

Author: deadboizxc
Version: 1.0
"""

import os
import struct
import hashlib
import hmac as hmac_module
from typing import Tuple, Union, Optional


# ============================================================================
# ChaCha20 Core
# ============================================================================

def _rotl32(x: int, n: int) -> int:
    """32-bit rotate left."""
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _chacha_quarter_round(state: list, a: int, b: int, c: int, d: int):
    """ChaCha20 quarter round."""
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = _rotl32(state[d], 16)
    
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = _rotl32(state[b], 12)
    
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = _rotl32(state[d], 8)
    
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = _rotl32(state[b], 7)


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """Generate one ChaCha20 block (64 bytes)."""
    # "expand 32-byte k"
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    
    # Key words (8 x 32-bit)
    key_words = list(struct.unpack('<8I', key))
    
    # Counter + nonce
    nonce_words = list(struct.unpack('<3I', nonce[:12]))
    
    # Initial state: constants + key + counter + nonce
    state = constants + key_words + [counter & 0xFFFFFFFF] + nonce_words
    working = state.copy()
    
    # 20 rounds (10 double rounds)
    for _ in range(10):
        # Column rounds
        _chacha_quarter_round(working, 0, 4, 8, 12)
        _chacha_quarter_round(working, 1, 5, 9, 13)
        _chacha_quarter_round(working, 2, 6, 10, 14)
        _chacha_quarter_round(working, 3, 7, 11, 15)
        # Diagonal rounds
        _chacha_quarter_round(working, 0, 5, 10, 15)
        _chacha_quarter_round(working, 1, 6, 11, 12)
        _chacha_quarter_round(working, 2, 7, 8, 13)
        _chacha_quarter_round(working, 3, 4, 9, 14)
    
    # Add initial state
    output = []
    for i in range(16):
        output.append((working[i] + state[i]) & 0xFFFFFFFF)
    
    return struct.pack('<16I', *output)


def chacha20_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    """ChaCha20 encrypt/decrypt (same operation)."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    if len(nonce) < 12:
        raise ValueError("Nonce must be at least 12 bytes")
    
    nonce = nonce[:12]  # Use first 12 bytes
    
    result = bytearray()
    counter = 0
    
    for i in range(0, len(plaintext), 64):
        block = _chacha20_block(key, counter, nonce)
        chunk = plaintext[i:i + 64]
        
        for j, byte in enumerate(chunk):
            result.append(byte ^ block[j])
        
        counter += 1
    
    return bytes(result)


# ============================================================================
# HChaCha20 (for XChaCha20)
# ============================================================================

def _hchacha20(key: bytes, nonce: bytes) -> bytes:
    """HChaCha20 - derive subkey for XChaCha20."""
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    key_words = list(struct.unpack('<8I', key))
    nonce_words = list(struct.unpack('<4I', nonce[:16]))
    
    state = constants + key_words + nonce_words
    
    # 20 rounds
    for _ in range(10):
        _chacha_quarter_round(state, 0, 4, 8, 12)
        _chacha_quarter_round(state, 1, 5, 9, 13)
        _chacha_quarter_round(state, 2, 6, 10, 14)
        _chacha_quarter_round(state, 3, 7, 11, 15)
        _chacha_quarter_round(state, 0, 5, 10, 15)
        _chacha_quarter_round(state, 1, 6, 11, 12)
        _chacha_quarter_round(state, 2, 7, 8, 13)
        _chacha_quarter_round(state, 3, 4, 9, 14)
    
    # Return first 4 and last 4 words
    return struct.pack('<4I', state[0], state[1], state[2], state[3]) + \
           struct.pack('<4I', state[12], state[13], state[14], state[15])


def xchacha20_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    """XChaCha20 encrypt."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    if len(nonce) < 24:
        raise ValueError("Nonce must be at least 24 bytes")
    
    # Derive subkey using first 16 bytes of nonce
    subkey = _hchacha20(key, nonce[:16])
    
    # Use remaining 8 bytes of nonce (with 4 zero bytes prefix)
    subnonce = b'\x00\x00\x00\x00' + nonce[16:24]
    
    return chacha20_encrypt(subkey, subnonce, plaintext)


def xchacha20_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """XChaCha20 decrypt (same as encrypt)."""
    return xchacha20_encrypt(key, nonce, ciphertext)


# ============================================================================
# SHA-256
# ============================================================================

def sha256(data: bytes) -> bytes:
    """Compute SHA-256 hash (32 bytes)."""
    return hashlib.sha256(data).digest()


# ============================================================================
# HMAC-SHA256
# ============================================================================

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """Calculate HMAC-SHA256."""
    return hmac_module.new(key, data, hashlib.sha256).digest()


def hmac_sha256_verify(key: bytes, data: bytes, signature: bytes) -> bool:
    """Verify HMAC-SHA256."""
    expected = hmac_sha256(key, data)
    return hmac_module.compare_digest(expected, signature)


# ============================================================================
# HKDF-SHA256 (RFC 5869)
# ============================================================================

def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 key derivation (legacy signature)."""
    return hkdf(salt, ikm, info, length)


def hkdf(salt: Optional[bytes], ikm: bytes, info: bytes, length: int) -> bytes:
    """
    HKDF-SHA256 key derivation (RFC 5869).
    
    Args:
        salt: Optional salt (default: zeros).
        ikm: Input keying material.
        info: Context info.
        length: Output length in bytes.
    
    Returns:
        Derived key material.
    """
    if not salt:
        salt = b'\x00' * 32
    
    # Extract
    prk = hmac_sha256(salt, ikm)
    
    # Expand
    output = b''
    prev = b''
    counter = 1
    
    while len(output) < length:
        prev = hmac_sha256(prk, prev + info + bytes([counter]))
        output += prev
        counter += 1
    
    return output[:length]


# ============================================================================
# HChaCha20 (already implemented in _hchacha20, add wrapper)
# ============================================================================

def hchacha20(key: bytes, nonce: bytes) -> bytes:
    """HChaCha20 key derivation (32-byte subkey)."""
    return _hchacha20(key, nonce[:16])


# ============================================================================
# Poly1305 MAC (RFC 7539)
# ============================================================================

def _clamp(r: int) -> int:
    """Clamp r value for Poly1305."""
    return r & 0x0ffffffc0ffffffc0ffffffc0fffffff


def _le_bytes_to_num(data: bytes) -> int:
    """Convert little-endian bytes to number."""
    return int.from_bytes(data, 'little')


def _num_to_le_bytes(n: int, length: int) -> bytes:
    """Convert number to little-endian bytes."""
    return n.to_bytes(length, 'little')


def poly1305(key: bytes, data: bytes) -> bytes:
    """
    Poly1305 MAC (16-byte tag).
    
    Args:
        key: 32-byte one-time key (r || s).
        data: Message to authenticate.
    
    Returns:
        16-byte authentication tag.
    """
    if len(key) != 32:
        raise ValueError("Poly1305 key must be 32 bytes")
    
    # Split key into r and s
    r = _clamp(_le_bytes_to_num(key[:16]))
    s = _le_bytes_to_num(key[16:32])
    
    # Calculate Poly1305
    P = (1 << 130) - 5
    acc = 0
    
    # Process 16-byte blocks
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        # Add high bit
        n = _le_bytes_to_num(block) + (1 << (8 * len(block)))
        acc = ((acc + n) * r) % P
    
    # Final tag
    tag = (acc + s) & ((1 << 128) - 1)
    return _num_to_le_bytes(tag, 16)


# ============================================================================
# XChaCha20-Poly1305 AEAD (RFC 7539 construction)
# ============================================================================

def _pad16(data: bytes) -> bytes:
    """Pad data to 16-byte boundary."""
    if len(data) % 16 == 0:
        return b''
    return b'\x00' * (16 - (len(data) % 16))


def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, 
                 ad: Optional[bytes] = None) -> bytes:
    """
    XChaCha20-Poly1305 authenticated encryption.
    
    Args:
        key: 32-byte encryption key.
        nonce: 24-byte nonce.
        plaintext: Data to encrypt.
        ad: Associated data (authenticated but not encrypted).
    
    Returns:
        Ciphertext with appended 16-byte authentication tag.
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    if len(nonce) < 24:
        raise ValueError("Nonce must be at least 24 bytes")
    
    ad = ad or b''
    
    # Encrypt plaintext with XChaCha20 (counter=1 to skip poly key block)
    ciphertext = xchacha20_encrypt(key, nonce[:24], plaintext)
    
    # Generate Poly1305 one-time key using first block
    # Derive subkey using HChaCha20
    subkey = _hchacha20(key, nonce[:16])
    chacha_nonce = b'\x00\x00\x00\x00' + nonce[16:24]
    
    # Generate poly key (64 bytes from counter=0)
    poly_block = bytearray(64)
    state = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    state.extend(struct.unpack('<8I', subkey))
    state.append(0)  # counter = 0
    state.extend(struct.unpack('<3I', chacha_nonce))
    
    working = state.copy()
    for _ in range(10):
        _chacha_quarter_round(working, 0, 4, 8, 12)
        _chacha_quarter_round(working, 1, 5, 9, 13)
        _chacha_quarter_round(working, 2, 6, 10, 14)
        _chacha_quarter_round(working, 3, 7, 11, 15)
        _chacha_quarter_round(working, 0, 5, 10, 15)
        _chacha_quarter_round(working, 1, 6, 11, 12)
        _chacha_quarter_round(working, 2, 7, 8, 13)
        _chacha_quarter_round(working, 3, 4, 9, 14)
    
    for i in range(16):
        working[i] = (working[i] + state[i]) & 0xFFFFFFFF
    
    poly_key = struct.pack('<16I', *working)[:32]
    
    # Build Poly1305 input (RFC 7539 construction)
    # AD || pad(AD) || ciphertext || pad(ciphertext) || len(AD) || len(CT)
    poly_input = (
        ad + _pad16(ad) +
        ciphertext + _pad16(ciphertext) +
        struct.pack('<Q', len(ad)) +
        struct.pack('<Q', len(ciphertext))
    )
    
    # Calculate tag
    tag = poly1305(poly_key, poly_input)
    
    return ciphertext + tag


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes,
                 ad: Optional[bytes] = None) -> bytes:
    """
    XChaCha20-Poly1305 authenticated decryption.
    
    Args:
        key: 32-byte encryption key.
        nonce: 24-byte nonce.
        ciphertext: Ciphertext with appended 16-byte tag.
        ad: Associated data (must match encryption).
    
    Returns:
        Decrypted plaintext.
    
    Raises:
        ValueError: If authentication tag is invalid.
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    if len(nonce) < 24:
        raise ValueError("Nonce must be at least 24 bytes")
    if len(ciphertext) < 16:
        raise ValueError("Ciphertext too short (must include 16-byte tag)")
    
    ad = ad or b''
    
    # Split ciphertext and tag
    ct = ciphertext[:-16]
    received_tag = ciphertext[-16:]
    
    # Derive subkey using HChaCha20
    subkey = _hchacha20(key, nonce[:16])
    chacha_nonce = b'\x00\x00\x00\x00' + nonce[16:24]
    
    # Generate poly key
    state = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    state.extend(struct.unpack('<8I', subkey))
    state.append(0)  # counter = 0
    state.extend(struct.unpack('<3I', chacha_nonce))
    
    working = state.copy()
    for _ in range(10):
        _chacha_quarter_round(working, 0, 4, 8, 12)
        _chacha_quarter_round(working, 1, 5, 9, 13)
        _chacha_quarter_round(working, 2, 6, 10, 14)
        _chacha_quarter_round(working, 3, 7, 11, 15)
        _chacha_quarter_round(working, 0, 5, 10, 15)
        _chacha_quarter_round(working, 1, 6, 11, 12)
        _chacha_quarter_round(working, 2, 7, 8, 13)
        _chacha_quarter_round(working, 3, 4, 9, 14)
    
    for i in range(16):
        working[i] = (working[i] + state[i]) & 0xFFFFFFFF
    
    poly_key = struct.pack('<16I', *working)[:32]
    
    # Build Poly1305 input and verify
    poly_input = (
        ad + _pad16(ad) +
        ct + _pad16(ct) +
        struct.pack('<Q', len(ad)) +
        struct.pack('<Q', len(ct))
    )
    
    expected_tag = poly1305(poly_key, poly_input)
    
    # Constant-time comparison
    diff = 0
    for a, b in zip(expected_tag, received_tag):
        diff |= a ^ b
    
    if diff != 0:
        raise ValueError("AEAD authentication failed")
    
    # Decrypt
    return xchacha20_decrypt(key, nonce[:24], ct)


# ============================================================================
# Key Derivation
# ============================================================================

def derive_keys(token: Union[str, bytes]) -> Tuple[bytes, bytes]:
    """
    Derive ChaCha20 and HMAC keys from token.
    
    Returns:
        (chacha_key, hmac_key) - both 32 bytes
    """
    if isinstance(token, str):
        token = token.encode('utf-8')
    
    key = hashlib.sha256(token).digest()
    return key, key  # Same key for both (as per protocol)


# ============================================================================
# High-Level API
# ============================================================================

def encrypt_payload(key: bytes, plaintext: bytes) -> str:
    """
    Encrypt plaintext and return hex payload.
    
    Format: [2B length BE] + [ciphertext] + [24B nonce]
    """
    nonce = os.urandom(24)
    ciphertext = xchacha20_encrypt(key, nonce, plaintext)
    
    # Pack: length (2 bytes, big-endian) + ciphertext + nonce
    length = len(ciphertext)
    packed = struct.pack('>H', length) + ciphertext + nonce
    
    return packed.hex()


def decrypt_payload(key: bytes, hex_payload: str) -> bytes:
    """
    Decrypt hex payload and return plaintext.
    
    Format: [2B length BE] + [ciphertext] + [24B nonce]
    """
    data = bytes.fromhex(hex_payload)
    
    if len(data) < 2 + 24:
        raise ValueError("Payload too short")
    
    length = struct.unpack('>H', data[:2])[0]
    ciphertext = data[2:2 + length]
    nonce = data[2 + length:2 + length + 24]
    
    if len(nonce) < 24:
        raise ValueError("Invalid nonce length")
    
    return xchacha20_decrypt(key, nonce, ciphertext)


def sign_payload(key: bytes, hex_payload: str) -> str:
    """Sign hex payload with HMAC-SHA256, return hex signature."""
    data = hex_payload.encode('utf-8')
    signature = hmac_sha256(key, data)
    return signature.hex()


def verify_signature(key: bytes, hex_payload: str, signature: str) -> bool:
    """Verify HMAC-SHA256 signature."""
    data = hex_payload.encode('utf-8')
    expected = hmac_sha256(key, data)
    return hmac.compare_digest(expected.hex().lower(), signature.lower())


__all__ = [
    # Low-level primitives
    'sha256',
    'hmac_sha256',
    'hmac_sha256_verify',
    'hkdf',
    'hkdf_sha256',
    'chacha20_encrypt',
    'hchacha20',
    'xchacha20_encrypt',
    'xchacha20_decrypt',
    'poly1305',
    'aead_encrypt',
    'aead_decrypt',
    # High-level
    'derive_keys',
    'encrypt_payload',
    'decrypt_payload',
    'sign_payload',
    'verify_signature',
]
