"""
EWSP Core Python Bindings
=========================

Unified cryptography and protocol handling for WakeLink.

Low-level API:
    sha256, hmac_sha256, hkdf, xchacha20, poly1305, aead_encrypt, aead_decrypt

High-level API:
    CryptoManager, PacketManager, ChainStateSnapshot

Example:
    from ewsp_core import CryptoManager, sha256, aead_encrypt
    
    # Low-level
    hash = sha256(b"hello")
    
    # High-level
    crypto = CryptoManager("your_token_32_characters_long!!")
    encrypted = crypto.encrypt(b"secret data")
"""

from .ewsp_core import (
    # Error handling
    EwspError,
    EwspException,
    
    # Low-level crypto
    sha256,
    hmac_sha256,
    hmac_verify,
    hkdf,
    xchacha20,
    hchacha20,
    poly1305,
    aead_encrypt,
    aead_decrypt,
    
    # Utilities
    constant_time_compare,
    secure_zero,
    random_bytes,
    bytes_to_hex,
    hex_to_bytes,
    is_native,
    
    # Version info
    get_version,
    get_protocol_version,
    get_error_message,
    
    # High-level managers
    CryptoManager,
    PacketManager,
    ChainStateSnapshot,
    
    # Convenience
    init,
    cleanup,
    create_ping_packet,
    create_wake_packet,
    create_info_packet,
    get_crypto_manager,
    
    # Constants
    EWSP_KEY_SIZE,
    EWSP_NONCE_SIZE,
    EWSP_HMAC_SIZE,
    EWSP_AEAD_TAG_SIZE,
)

__all__ = [
    # Error handling
    'EwspError',
    'EwspException',
    
    # Low-level crypto
    'sha256',
    'hmac_sha256',
    'hmac_verify',
    'hkdf',
    'xchacha20',
    'hchacha20',
    'poly1305',
    'aead_encrypt',
    'aead_decrypt',
    
    # Utilities
    'constant_time_compare',
    'secure_zero',
    'random_bytes',
    'bytes_to_hex',
    'hex_to_bytes',
    'is_native',
    
    # Version info
    'get_version',
    'get_protocol_version',
    'get_error_message',
    
    # High-level managers
    'CryptoManager',
    'PacketManager',
    'ChainStateSnapshot',
    
    # Convenience
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

__version__ = '1.0.0'
