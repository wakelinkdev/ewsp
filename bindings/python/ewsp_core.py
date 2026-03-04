"""
EWSP Core Python Bindings
=========================

Unified Python ctypes binding to the ewsp-core C library v1.0.

Features:
- Low-level crypto: SHA256, HMAC, HKDF, XChaCha20, Poly1305
- AEAD: XChaCha20-Poly1305 authenticated encryption (RFC 7539)
- Sessions: Mutual auth, key ratcheting, replay protection
- Packets: Blockchain chaining, signature verification
- Pure Python fallback when C library unavailable

API Levels:
1. Low-level functions: sha256(), hmac_sha256(), xchacha20(), aead_encrypt()
2. High-level managers: CryptoManager, PacketManager, SessionManager
3. Convenience: create_ping_packet(), get_crypto_manager()

Usage:
    # Low-level crypto
    from ewsp_core import sha256, hmac_sha256, xchacha20, aead_encrypt
    hash_bytes = sha256(b"hello")
    
    # High-level manager
    from ewsp_core import CryptoManager
    crypto = CryptoManager("your_device_token_32chars")
    encrypted = crypto.encrypt(b"hello world")
    
    # Check native vs fallback
    from ewsp_core import is_native
    print(f"Using native library: {is_native()}")

Build the C library:
    cd ewsp-core && cmake -B build && cmake --build build

Author: deadboizxc
Version: 1.0
"""

import os
import sys
import ctypes
import struct
import secrets
import time
import platform
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Optional, Dict, Any, Tuple, Union

# ============================================================================
# Constants
# ============================================================================

EWSP_KEY_SIZE = 32
EWSP_NONCE_SIZE = 24
EWSP_HMAC_SIZE = 32
EWSP_POLY1305_TAG_SIZE = 16
EWSP_AEAD_TAG_SIZE = 16
EWSP_SESSION_ID_SIZE = 16
EWSP_SESSION_RANDOM_SIZE = 32
EWSP_SESSION_PROOF_SIZE = 32

# ============================================================================
# Error Codes
# ============================================================================

class EwspError(IntEnum):
    """EWSP error codes matching ewsp_errors.h."""
    OK = 0
    INVALID_PARAM = 1
    INVALID_LENGTH = 2
    BUFFER_TOO_SMALL = 3
    MEM_ALLOC_FAILED = 4
    INVALID_STATE = 5
    NOT_INITIALIZED = 6
    CRYPTO_ERROR = 10
    INVALID_KEY = 11
    INVALID_NONCE = 12
    AUTH_FAILED = 13
    CHAIN_ERROR = 20
    SEQUENCE_MISMATCH = 21
    HASH_MISMATCH = 22
    REPLAY_DETECTED = 23
    MAX_SEQUENCE = 24
    PACKET_ERROR = 30
    INVALID_FORMAT = 31
    INVALID_SIGNATURE = 32
    INVALID_TIMESTAMP = 33
    JSON_ERROR = 40
    JSON_PARSE = 41
    JSON_FORMAT = 42
    SESSION_ERROR = 50
    SESSION_EXPIRED = 51
    SESSION_NOT_FOUND = 52
    SESSION_LIMIT = 53


class EwspException(Exception):
    """Exception for EWSP errors."""
    
    def __init__(self, code: EwspError, message: str = ""):
        self.code = code
        self.message = message or f"EWSP error: {code.name}"
        super().__init__(self.message)


# ============================================================================
# Library Loading
# ============================================================================

def _find_library() -> str:
    """Find the EWSP Core shared library."""
    lib_dir = Path(__file__).parent
    
    system = platform.system().lower()
    
    if system == 'windows':
        lib_names = ['ewsp_core.dll', 'libewsp_core.dll']
    elif system == 'darwin':
        lib_names = ['libewsp_core.dylib']
    else:
        lib_names = ['libewsp_core.so']
    
    # Search paths in priority order
    search_paths = [
        lib_dir / 'lib',
        lib_dir,
        lib_dir.parent / 'build',
        lib_dir.parent / 'build' / 'Release',
        lib_dir.parent / 'build' / 'Debug',
        lib_dir.parent / 'build' / 'lib',
        lib_dir.parent.parent / 'build',
        lib_dir.parent.parent / 'build' / 'lib',
        Path.cwd() / 'lib',
        Path.cwd(),
    ]
    
    for path in search_paths:
        if not path.exists():
            continue
        for name in lib_names:
            lib_path = path / name
            if lib_path.exists():
                return str(lib_path)
    
    # Try system paths
    for name in lib_names:
        try:
            ctypes.CDLL(name)
            return name
        except OSError:
            continue
    
    return None


# Library singleton
_lib = None
_lib_loaded = False


def get_lib():
    """Get loaded library instance."""
    global _lib, _lib_loaded
    
    if _lib is not None:
        return _lib
    
    if _lib_loaded:
        raise RuntimeError("EWSP Core library not available")
    
    _lib_loaded = True
    lib_path = _find_library()
    
    if lib_path is None:
        raise RuntimeError(
            "EWSP Core library not found.\n"
            "Build with: cd ewsp-core && cmake -B build && cmake --build build"
        )
    
    _lib = ctypes.CDLL(lib_path)
    _setup_function_prototypes(_lib)
    return _lib


def _setup_function_prototypes(lib):
    """Configure ctypes prototypes for all library functions."""
    
    # ═══════════════════════════════════════════════════════════════════════
    # Version info
    # ═══════════════════════════════════════════════════════════════════════
    
    lib.ewsp_version.argtypes = []
    lib.ewsp_version.restype = ctypes.c_char_p
    
    lib.ewsp_protocol_version.argtypes = []
    lib.ewsp_protocol_version.restype = ctypes.c_char_p
    
    # ═══════════════════════════════════════════════════════════════════════
    # SHA-256
    # ═══════════════════════════════════════════════════════════════════════
    
    lib.ewsp_sha256.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
    lib.ewsp_sha256.restype = None
    
    # ═══════════════════════════════════════════════════════════════════════
    # HMAC-SHA256
    # ═══════════════════════════════════════════════════════════════════════
    
    lib.ewsp_hmac_sha256.argtypes = [
        ctypes.c_void_p, ctypes.c_size_t,  # key, key_len
        ctypes.c_void_p, ctypes.c_size_t,  # data, data_len
        ctypes.c_void_p                     # mac[32]
    ]
    lib.ewsp_hmac_sha256.restype = None
    
    lib.ewsp_hmac_verify.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    lib.ewsp_hmac_verify.restype = ctypes.c_int
    
    # ═══════════════════════════════════════════════════════════════════════
    # HKDF-SHA256
    # ═══════════════════════════════════════════════════════════════════════
    
    lib.ewsp_hkdf.argtypes = [
        ctypes.c_void_p, ctypes.c_size_t,  # salt, salt_len
        ctypes.c_void_p, ctypes.c_size_t,  # ikm, ikm_len
        ctypes.c_void_p, ctypes.c_size_t,  # info, info_len
        ctypes.c_void_p, ctypes.c_size_t   # okm, okm_len
    ]
    lib.ewsp_hkdf.restype = None
    
    # ═══════════════════════════════════════════════════════════════════════
    # ChaCha20 / XChaCha20
    # ═══════════════════════════════════════════════════════════════════════
    
    lib.ewsp_chacha20.argtypes = [
        ctypes.c_void_p,   # key[32]
        ctypes.c_void_p,   # nonce[12]
        ctypes.c_uint32,   # counter
        ctypes.c_void_p,   # input
        ctypes.c_void_p,   # output
        ctypes.c_size_t    # len
    ]
    lib.ewsp_chacha20.restype = None
    
    lib.ewsp_hchacha20.argtypes = [
        ctypes.c_void_p,   # key[32]
        ctypes.c_void_p,   # nonce[16]
        ctypes.c_void_p    # subkey[32]
    ]
    lib.ewsp_hchacha20.restype = None
    
    lib.ewsp_xchacha20.argtypes = [
        ctypes.c_void_p,   # key[32]
        ctypes.c_void_p,   # nonce[24]
        ctypes.c_uint32,   # counter
        ctypes.c_void_p,   # input
        ctypes.c_void_p,   # output
        ctypes.c_size_t    # len
    ]
    lib.ewsp_xchacha20.restype = None
    
    # ═══════════════════════════════════════════════════════════════════════
    # Poly1305
    # ═══════════════════════════════════════════════════════════════════════
    
    lib.ewsp_poly1305.argtypes = [
        ctypes.c_void_p,   # key[32]
        ctypes.c_void_p,   # data
        ctypes.c_size_t,   # len
        ctypes.c_void_p    # tag[16]
    ]
    lib.ewsp_poly1305.restype = None
    
    # ═══════════════════════════════════════════════════════════════════════
    # XChaCha20-Poly1305 AEAD
    # ═══════════════════════════════════════════════════════════════════════
    
    lib.ewsp_aead_encrypt.argtypes = [
        ctypes.c_void_p,   # key[32]
        ctypes.c_void_p,   # nonce[24]
        ctypes.c_void_p,   # ad
        ctypes.c_size_t,   # ad_len
        ctypes.c_void_p,   # plaintext
        ctypes.c_size_t,   # plaintext_len
        ctypes.c_void_p    # ciphertext (plaintext_len + 16)
    ]
    lib.ewsp_aead_encrypt.restype = ctypes.c_int
    
    lib.ewsp_aead_decrypt.argtypes = [
        ctypes.c_void_p,   # key[32]
        ctypes.c_void_p,   # nonce[24]
        ctypes.c_void_p,   # ad
        ctypes.c_size_t,   # ad_len
        ctypes.c_void_p,   # ciphertext (with tag)
        ctypes.c_size_t,   # ciphertext_len (including 16-byte tag)
        ctypes.c_void_p    # plaintext
    ]
    lib.ewsp_aead_decrypt.restype = ctypes.c_int
    
    # ═══════════════════════════════════════════════════════════════════════
    # Utility functions
    # ═══════════════════════════════════════════════════════════════════════
    
    lib.ewsp_constant_time_compare.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t
    ]
    lib.ewsp_constant_time_compare.restype = ctypes.c_int
    
    lib.ewsp_secure_zero.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    lib.ewsp_secure_zero.restype = None
    
    lib.ewsp_bytes_to_hex.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p]
    lib.ewsp_bytes_to_hex.restype = None
    
    lib.ewsp_hex_to_bytes.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t]
    lib.ewsp_hex_to_bytes.restype = ctypes.c_int
    
    lib.ewsp_random_bytes.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    lib.ewsp_random_bytes.restype = ctypes.c_int
    
    # ═══════════════════════════════════════════════════════════════════════
    # Init/Cleanup
    # ═══════════════════════════════════════════════════════════════════════
    
    lib.ewsp_init.argtypes = []
    lib.ewsp_init.restype = ctypes.c_int
    
    lib.ewsp_cleanup.argtypes = []
    lib.ewsp_cleanup.restype = None
    
    # ═══════════════════════════════════════════════════════════════════════
    # Error functions
    # ═══════════════════════════════════════════════════════════════════════
    
    lib.ewsp_error_message.argtypes = [ctypes.c_int]
    lib.ewsp_error_message.restype = ctypes.c_char_p
    
    lib.ewsp_error_code_str.argtypes = [ctypes.c_int]
    lib.ewsp_error_code_str.restype = ctypes.c_char_p


# ============================================================================
# ctypes Structures
# ============================================================================

class CryptoContext(ctypes.Structure):
    """Crypto context structure from ewsp_crypto.h."""
    _fields_ = [
        ("chacha_key", ctypes.c_uint8 * 32),
        ("hmac_key", ctypes.c_uint8 * 32),
        ("initialized", ctypes.c_bool)
    ]


class ChainSnapshot(ctypes.Structure):
    """Chain state snapshot for persistence."""
    _fields_ = [
        ("tx_sequence", ctypes.c_uint64),
        ("tx_hash", ctypes.c_char * 65),
        ("rx_sequence", ctypes.c_uint64),
        ("rx_hash", ctypes.c_char * 65),
        ("last_received_hash", ctypes.c_char * 65)
    ]


class PacketContext(ctypes.Structure):
    """Packet context structure."""
    _fields_ = [
        ("crypto", CryptoContext),
        ("device_id", ctypes.c_char * 64),
        ("tx_sequence", ctypes.c_uint64),
        ("tx_hash", ctypes.c_uint8 * 32),
        ("rx_sequence", ctypes.c_uint64),
        ("rx_hash", ctypes.c_uint8 * 32),
        ("last_received_hash", ctypes.c_uint8 * 32),
        ("initialized", ctypes.c_bool)
    ]


# ============================================================================
# Low-Level Crypto Functions (Auto-fallback)
# ============================================================================

_use_native = None


def is_native() -> bool:
    """Check if native library is being used."""
    global _use_native
    if _use_native is None:
        try:
            get_lib()
            _use_native = True
        except RuntimeError:
            _use_native = False
    return _use_native


def _get_native_or_none():
    """Get native library or None."""
    try:
        return get_lib()
    except RuntimeError:
        return None


# --- SHA-256 ---

def sha256(data: bytes) -> bytes:
    """Compute SHA-256 hash (32 bytes)."""
    lib = _get_native_or_none()
    if lib:
        result = ctypes.create_string_buffer(32)
        lib.ewsp_sha256(data, len(data), result)
        return result.raw
    
    # Pure Python fallback
    from .crypto_pure import sha256 as pure_sha256
    return pure_sha256(data)


# --- HMAC-SHA256 ---

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """Compute HMAC-SHA256 (32 bytes)."""
    lib = _get_native_or_none()
    if lib:
        mac = ctypes.create_string_buffer(32)
        lib.ewsp_hmac_sha256(key, len(key), data, len(data), mac)
        return mac.raw
    
    # Pure Python fallback
    from .crypto_pure import hmac_sha256 as pure_hmac
    return pure_hmac(key, data)


def hmac_verify(mac1: bytes, mac2: bytes) -> bool:
    """Constant-time HMAC verification."""
    if len(mac1) != 32 or len(mac2) != 32:
        return False
    
    lib = _get_native_or_none()
    if lib:
        return lib.ewsp_hmac_verify(mac1, mac2) == 1
    
    # Pure Python fallback
    return constant_time_compare(mac1, mac2)


# --- HKDF-SHA256 ---

def hkdf(salt: Optional[bytes], ikm: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 key derivation (RFC 5869)."""
    lib = _get_native_or_none()
    if lib:
        okm = ctypes.create_string_buffer(length)
        salt_ptr = salt if salt else None
        salt_len = len(salt) if salt else 0
        lib.ewsp_hkdf(salt_ptr, salt_len, ikm, len(ikm), info, len(info), okm, length)
        return okm.raw
    
    # Pure Python fallback
    from .crypto_pure import hkdf as pure_hkdf
    return pure_hkdf(salt, ikm, info, length)


# --- XChaCha20 ---

def xchacha20(key: bytes, nonce: bytes, data: bytes, counter: int = 0) -> bytes:
    """XChaCha20 encrypt/decrypt with 24-byte nonce."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    if len(nonce) < 24:
        raise ValueError("Nonce must be at least 24 bytes")
    
    lib = _get_native_or_none()
    if lib:
        output = ctypes.create_string_buffer(len(data))
        lib.ewsp_xchacha20(key, nonce[:24], counter, data, output, len(data))
        return output.raw
    
    # Pure Python fallback
    from .crypto_pure import xchacha20_encrypt
    return xchacha20_encrypt(key, nonce[:24], data)


def hchacha20(key: bytes, nonce: bytes) -> bytes:
    """HChaCha20 key derivation (32-byte subkey)."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    if len(nonce) < 16:
        raise ValueError("Nonce must be at least 16 bytes")
    
    lib = _get_native_or_none()
    if lib:
        subkey = ctypes.create_string_buffer(32)
        lib.ewsp_hchacha20(key, nonce[:16], subkey)
        return subkey.raw
    
    # Pure Python fallback
    from .crypto_pure import hchacha20 as pure_hchacha20
    return pure_hchacha20(key, nonce[:16])


# --- Poly1305 ---

def poly1305(key: bytes, data: bytes) -> bytes:
    """Poly1305 MAC (16-byte tag)."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    
    lib = _get_native_or_none()
    if lib:
        tag = ctypes.create_string_buffer(16)
        lib.ewsp_poly1305(key, data, len(data), tag)
        return tag.raw
    
    # Pure Python fallback
    from .crypto_pure import poly1305 as pure_poly1305
    return pure_poly1305(key, data)


# --- XChaCha20-Poly1305 AEAD ---

def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, 
                 ad: Optional[bytes] = None) -> bytes:
    """
    XChaCha20-Poly1305 authenticated encryption.
    
    Args:
        key: 32-byte encryption key.
        nonce: 24-byte unique nonce (MUST be unique per key).
        plaintext: Data to encrypt.
        ad: Associated data (authenticated but not encrypted).
    
    Returns:
        Ciphertext with appended 16-byte authentication tag.
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    if len(nonce) < 24:
        raise ValueError("Nonce must be at least 24 bytes")
    
    ad_bytes = ad if ad else b''
    
    lib = _get_native_or_none()
    if lib:
        ciphertext = ctypes.create_string_buffer(len(plaintext) + 16)
        result = lib.ewsp_aead_encrypt(
            key, nonce[:24], ad_bytes, len(ad_bytes),
            plaintext, len(plaintext), ciphertext
        )
        if result != 0:
            raise EwspException(EwspError(result), "AEAD encryption failed")
        return ciphertext.raw
    
    # Pure Python fallback
    from .crypto_pure import aead_encrypt as pure_aead_encrypt
    return pure_aead_encrypt(key, nonce[:24], plaintext, ad_bytes)


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes,
                 ad: Optional[bytes] = None) -> bytes:
    """
    XChaCha20-Poly1305 authenticated decryption.
    
    Args:
        key: 32-byte encryption key.
        nonce: 24-byte nonce (same as used for encryption).
        ciphertext: Ciphertext with appended 16-byte tag.
        ad: Associated data (must match encryption).
    
    Returns:
        Decrypted plaintext.
    
    Raises:
        EwspException: If authentication tag is invalid.
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    if len(nonce) < 24:
        raise ValueError("Nonce must be at least 24 bytes")
    if len(ciphertext) < 16:
        raise ValueError("Ciphertext too short (must include 16-byte tag)")
    
    ad_bytes = ad if ad else b''
    plaintext_len = len(ciphertext) - 16
    
    lib = _get_native_or_none()
    if lib:
        plaintext = ctypes.create_string_buffer(plaintext_len)
        result = lib.ewsp_aead_decrypt(
            key, nonce[:24], ad_bytes, len(ad_bytes),
            ciphertext, len(ciphertext), plaintext
        )
        if result != 0:
            raise EwspException(EwspError.AUTH_FAILED, "AEAD authentication failed")
        return plaintext.raw
    
    # Pure Python fallback
    from .crypto_pure import aead_decrypt as pure_aead_decrypt
    return pure_aead_decrypt(key, nonce[:24], ciphertext, ad_bytes)


# --- Utility Functions ---

def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time byte comparison."""
    if len(a) != len(b):
        return False
    
    lib = _get_native_or_none()
    if lib:
        return lib.ewsp_constant_time_compare(a, b, len(a)) == 1
    
    # Pure Python fallback
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def secure_zero(data: bytearray) -> None:
    """Securely zero memory."""
    lib = _get_native_or_none()
    if lib and isinstance(data, (bytearray, ctypes.Array)):
        lib.ewsp_secure_zero(ctypes.addressof(ctypes.c_char.from_buffer(data)), len(data))
    else:
        for i in range(len(data)):
            data[i] = 0


def random_bytes(length: int) -> bytes:
    """Generate cryptographically secure random bytes."""
    lib = _get_native_or_none()
    if lib:
        buf = ctypes.create_string_buffer(length)
        result = lib.ewsp_random_bytes(buf, length)
        if result == 0:
            return buf.raw
    
    # Pure Python fallback
    return secrets.token_bytes(length)


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string."""
    return data.hex()


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes."""
    return bytes.fromhex(hex_str)


# ============================================================================
# High-Level API: Version info
# ============================================================================

def get_version() -> str:
    """Get EWSP Core library version."""
    lib = _get_native_or_none()
    if lib:
        return lib.ewsp_version().decode('utf-8')
    return "1.0.0-python"


def get_protocol_version() -> str:
    """Get EWSP protocol version."""
    lib = _get_native_or_none()
    if lib:
        return lib.ewsp_protocol_version().decode('utf-8')
    return "1.0"


def get_error_message(code: int) -> str:
    """Get human-readable error message."""
    lib = _get_native_or_none()
    if lib:
        msg = lib.ewsp_error_message(code)
        return msg.decode('utf-8') if msg else f"Unknown error {code}"
    return f"Error {code}"


# ============================================================================
# High-Level API: CryptoManager
# ============================================================================

@dataclass
class ChainStateSnapshot:
    """Python representation of chain state."""
    tx_sequence: int
    tx_hash: str
    rx_sequence: int
    rx_hash: str
    last_received_hash: str


class CryptoManager:
    """
    High-level crypto manager using EWSP Core library.
    
    Provides encryption, decryption, and HMAC operations using
    keys derived from device token.
    """
    
    KEY_SIZE = 32
    NONCE_SIZE = 24
    HMAC_SIZE = 32
    
    def __init__(self, token: str):
        """
        Initialize crypto manager with device token.
        
        Args:
            token: Device token (min 32 characters).
        """
        if len(token) < 32:
            raise ValueError("Token must be at least 32 characters")
        
        token_bytes = token.encode('utf-8')
        
        # Derive master key from token
        self._master_key = sha256(token_bytes)
        
        # Derive separate keys for encryption and authentication (CRYPTO-03 fix)
        self._chacha_key = hkdf(None, self._master_key, b"wakelink_encryption_v2", 32)
        self._hmac_key = hkdf(None, self._master_key, b"wakelink_authentication_v2", 32)
    
    def __del__(self):
        """Cleanup sensitive key material."""
        if hasattr(self, '_master_key'):
            self._master_key = bytes(32)
        if hasattr(self, '_chacha_key'):
            self._chacha_key = bytes(32)
        if hasattr(self, '_hmac_key'):
            self._hmac_key = bytes(32)
    
    def encrypt(self, plaintext: bytes) -> str:
        """
        Encrypt data using XChaCha20.
        
        Returns hex payload: [2B length BE] + [ciphertext] + [24B nonce]
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        nonce = random_bytes(self.NONCE_SIZE)
        ciphertext = xchacha20(self._chacha_key, nonce, plaintext)
        
        # Build payload
        length = len(ciphertext)
        payload = struct.pack('>H', length) + ciphertext + nonce
        return payload.hex()
    
    def decrypt(self, hex_payload: str) -> bytes:
        """Decrypt hex payload to plaintext."""
        payload = bytes.fromhex(hex_payload)
        
        if len(payload) < 2 + self.NONCE_SIZE:
            raise ValueError("Payload too short")
        
        length = struct.unpack('>H', payload[:2])[0]
        
        if len(payload) < 2 + length + self.NONCE_SIZE:
            raise ValueError("Invalid payload length")
        
        ciphertext = payload[2:2 + length]
        nonce = payload[2 + length:2 + length + self.NONCE_SIZE]
        
        return xchacha20(self._chacha_key, nonce, ciphertext)
    
    def sign(self, data: Union[bytes, str]) -> str:
        """Calculate HMAC-SHA256 signature (hex)."""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        mac = hmac_sha256(self._hmac_key, data)
        return mac.hex()
    
    def verify(self, data: Union[bytes, str], signature: str) -> bool:
        """Verify HMAC-SHA256 signature."""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        if len(signature) != 64:
            return False
        
        try:
            expected = hmac_sha256(self._hmac_key, data)
            received = bytes.fromhex(signature)
            return hmac_verify(expected, received)
        except ValueError:
            return False
    
    def derive_key(self, info: str, length: int = 32) -> bytes:
        """Derive key using HKDF."""
        return hkdf(None, self._master_key, info.encode('utf-8'), length)
    
    # --- AEAD methods ---
    
    def aead_encrypt(self, plaintext: bytes, ad: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        AEAD encrypt with XChaCha20-Poly1305.
        
        Returns:
            Tuple of (ciphertext_with_tag, nonce).
        """
        nonce = random_bytes(24)
        ct = aead_encrypt(self._chacha_key, nonce, plaintext, ad)
        return ct, nonce
    
    def aead_decrypt(self, ciphertext: bytes, nonce: bytes, 
                     ad: Optional[bytes] = None) -> bytes:
        """AEAD decrypt with XChaCha20-Poly1305."""
        return aead_decrypt(self._chacha_key, nonce, ciphertext, ad)


# ============================================================================
# High-Level API: PacketManager
# ============================================================================

class PacketManager:
    """
    High-level packet manager using EWSP Core library.
    
    Handles packet creation with blockchain chaining.
    """
    
    def __init__(self, token: str, device_id: str):
        """
        Initialize packet manager.
        
        Args:
            token: Device token.
            device_id: Target device identifier.
        """
        self._crypto = CryptoManager(token)
        self._device_id = device_id
        
        # Chain state
        self._tx_sequence = 0
        self._tx_hash = bytes(32)  # Genesis
        self._rx_sequence = 0
        self._rx_hash = bytes(32)  # Genesis
    
    @property
    def device_id(self) -> str:
        return self._device_id
    
    def create_command(self, command: str, data: Optional[Dict[str, Any]] = None) -> str:
        """
        Create an encrypted command packet.
        
        Args:
            command: Command name (e.g., "ping", "wake", "info").
            data: Optional command data.
        
        Returns:
            JSON packet string ready to send.
        """
        import json
        
        # Generate request ID
        request_id = secrets.token_hex(8)
        
        # Build inner packet
        inner = {
            "command": command,
            "request_id": request_id,
            "timestamp": int(time.time() * 1000)
        }
        if data:
            inner["data"] = data
        
        inner_json = json.dumps(inner, separators=(',', ':'))
        
        # Encrypt
        payload = self._crypto.encrypt(inner_json.encode('utf-8'))
        
        # Calculate HMAC
        signature = self._crypto.sign(payload)
        
        # Build outer packet with chain info
        self._tx_sequence += 1
        chain_data = struct.pack('>Q', self._tx_sequence) + self._tx_hash + payload.encode('utf-8')
        self._tx_hash = sha256(chain_data)
        
        outer = {
            "device_id": self._device_id,
            "payload": payload,
            "signature": signature,
            "request_counter": self._tx_sequence,
            "chain_hash": self._tx_hash.hex(),
            "version": "1.0"
        }
        
        return json.dumps(outer, separators=(',', ':'))
    
    def reset_chains(self):
        """Reset TX and RX chains to genesis state."""
        self._tx_sequence = 0
        self._tx_hash = bytes(32)
        self._rx_sequence = 0
        self._rx_hash = bytes(32)
    
    def export_state(self) -> ChainStateSnapshot:
        """Export chain state for persistence."""
        return ChainStateSnapshot(
            tx_sequence=self._tx_sequence,
            tx_hash=self._tx_hash.hex(),
            rx_sequence=self._rx_sequence,
            rx_hash=self._rx_hash.hex(),
            last_received_hash=""
        )
    
    def import_state(self, state: ChainStateSnapshot):
        """Import chain state from persistence."""
        self._tx_sequence = state.tx_sequence
        self._tx_hash = bytes.fromhex(state.tx_hash)
        self._rx_sequence = state.rx_sequence
        self._rx_hash = bytes.fromhex(state.rx_hash)


# ============================================================================
# High-Level API: Convenience Functions
# ============================================================================

def init():
    """Initialize EWSP Core library."""
    lib = _get_native_or_none()
    if lib:
        err = lib.ewsp_init()
        if err != 0:
            raise EwspException(EwspError(err), "Failed to initialize EWSP Core")


def cleanup():
    """Cleanup EWSP Core library."""
    lib = _get_native_or_none()
    if lib:
        lib.ewsp_cleanup()


def create_ping_packet(token: str, device_id: str) -> str:
    """Create a ping command packet."""
    pm = PacketManager(token, device_id)
    return pm.create_command("ping")


def create_wake_packet(token: str, device_id: str, mac: str) -> str:
    """Create a wake command packet."""
    pm = PacketManager(token, device_id)
    return pm.create_command("wake", {"mac": mac})


def create_info_packet(token: str, device_id: str) -> str:
    """Create an info command packet."""
    pm = PacketManager(token, device_id)
    return pm.create_command("info")


def get_crypto_manager(token: str) -> CryptoManager:
    """
    Get a crypto manager (uses native library if available).
    
    Legacy function for backward compatibility.
    """
    return CryptoManager(token)


# ============================================================================
# Exports
# ============================================================================

__all__ = [
    # Error handling
    'EwspError',
    'EwspException',
    
    # Low-level crypto functions
    'sha256',
    'hmac_sha256',
    'hmac_verify',
    'hkdf',
    'xchacha20',
    'hchacha20',
    'poly1305',
    'aead_encrypt',
    'aead_decrypt',
    
    # Utility functions
    'constant_time_compare',
    'secure_zero',
    'random_bytes',
    'bytes_to_hex',
    'hex_to_bytes',
    
    # Version info
    'get_version',
    'get_protocol_version',
    'get_error_message',
    'is_native',
    
    # High-level managers
    'CryptoManager',
    'PacketManager',
    'ChainStateSnapshot',
    
    # Convenience functions
    'init',
    'cleanup',
    'create_ping_packet',
    'create_wake_packet',
    'create_info_packet',
    'get_crypto_manager',
    
    # Constants
    'EWSP_KEY_SIZE',
    'EWSP_NONCE_SIZE',
    'EWSP_HMAC_SIZE',
    'EWSP_AEAD_TAG_SIZE',
]
