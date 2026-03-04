"""
EWSP Core Python Binding Tests
==============================

Comprehensive tests for ewsp_core Python bindings.

Covers:
- Low-level crypto: SHA256, HMAC, HKDF, XChaCha20
- AEAD: XChaCha20-Poly1305
- High-level: CryptoManager, PacketManager
- Fallback mode (pure Python)

Run tests:
    cd ewsp/bindings/python
    pytest tests/ -v

Author: deadboizxc
"""

import sys
import struct
import secrets
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest


class TestSHA256:
    """SHA-256 hash tests."""
    
    def test_sha256_abc(self):
        """Test SHA-256 with 'abc' (NIST test vector)."""
        from ewsp_core import sha256
        result = sha256(b"abc")
        expected = bytes.fromhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        assert result == expected
    
    def test_sha256_empty(self):
        """Test SHA-256 with empty input."""
        from ewsp_core import sha256
        result = sha256(b"")
        expected = bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert result == expected
    
    def test_sha256_long(self):
        """Test SHA-256 with longer input."""
        from ewsp_core import sha256
        result = sha256(b"The quick brown fox jumps over the lazy dog")
        expected = bytes.fromhex("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592")
        assert result == expected


class TestHMAC:
    """HMAC-SHA256 tests."""
    
    def test_hmac_basic(self):
        """Test HMAC-SHA256 (RFC 4231 test vector)."""
        from ewsp_core import hmac_sha256
        key = b"key"
        data = b"The quick brown fox jumps over the lazy dog"
        result = hmac_sha256(key, data)
        expected = bytes.fromhex("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")
        assert result == expected
    
    def test_hmac_verify_valid(self):
        """Test HMAC verification with valid MAC."""
        from ewsp_core import hmac_sha256, hmac_verify
        key = bytes(32)
        data = b"test message"
        mac = hmac_sha256(key, data)
        assert hmac_verify(mac, mac) is True
    
    def test_hmac_verify_invalid(self):
        """Test HMAC verification with invalid MAC."""
        from ewsp_core import hmac_sha256, hmac_verify
        key = bytes(32)
        data = b"test message"
        mac = hmac_sha256(key, data)
        bad_mac = bytes(32)
        assert hmac_verify(mac, bad_mac) is False


class TestHKDF:
    """HKDF-SHA256 tests."""
    
    def test_hkdf_basic(self):
        """Test HKDF basic derivation."""
        from ewsp_core import hkdf
        ikm = b"input keying material"
        salt = b"salt"
        info = b"context info"
        okm = hkdf(salt, ikm, info, 32)
        assert len(okm) == 32
        assert okm != bytes(32)
    
    def test_hkdf_no_salt(self):
        """Test HKDF with no salt."""
        from ewsp_core import hkdf
        ikm = b"input keying material"
        info = b"context info"
        okm = hkdf(None, ikm, info, 32)
        assert len(okm) == 32
    
    def test_hkdf_different_lengths(self):
        """Test HKDF with different output lengths."""
        from ewsp_core import hkdf
        ikm = b"input keying material"
        info = b"context info"
        
        okm16 = hkdf(None, ikm, info, 16)
        okm32 = hkdf(None, ikm, info, 32)
        okm64 = hkdf(None, ikm, info, 64)
        
        assert len(okm16) == 16
        assert len(okm32) == 32
        assert len(okm64) == 64
        
        # okm32 should start with okm16
        assert okm32[:16] == okm16


class TestXChaCha20:
    """XChaCha20 cipher tests."""
    
    def test_xchacha20_roundtrip(self):
        """Test XChaCha20 encrypt/decrypt roundtrip."""
        from ewsp_core import xchacha20
        
        key = bytes(32)
        nonce = bytes(24)
        plaintext = b"Hello, XChaCha20!"
        
        ciphertext = xchacha20(key, nonce, plaintext)
        decrypted = xchacha20(key, nonce, ciphertext)
        
        assert decrypted == plaintext
        assert ciphertext != plaintext
    
    def test_xchacha20_deterministic(self):
        """Test XChaCha20 produces same output for same inputs."""
        from ewsp_core import xchacha20
        
        key = bytes(32)
        nonce = bytes(24)
        plaintext = b"test data"
        
        ct1 = xchacha20(key, nonce, plaintext)
        ct2 = xchacha20(key, nonce, plaintext)
        
        assert ct1 == ct2
    
    def test_xchacha20_different_keys(self):
        """Test XChaCha20 produces different output for different keys."""
        from ewsp_core import xchacha20
        
        key1 = bytes(32)
        key2 = bytes([1] + [0]*31)
        nonce = bytes(24)
        plaintext = b"test data"
        
        ct1 = xchacha20(key1, nonce, plaintext)
        ct2 = xchacha20(key2, nonce, plaintext)
        
        assert ct1 != ct2
    
    def test_xchacha20_invalid_key(self):
        """Test XChaCha20 rejects invalid key."""
        from ewsp_core import xchacha20
        
        with pytest.raises(ValueError, match="Key must be 32 bytes"):
            xchacha20(b"short", bytes(24), b"data")
    
    def test_xchacha20_invalid_nonce(self):
        """Test XChaCha20 rejects invalid nonce."""
        from ewsp_core import xchacha20
        
        with pytest.raises(ValueError, match="Nonce must be at least 24 bytes"):
            xchacha20(bytes(32), b"short", b"data")


class TestPoly1305:
    """Poly1305 MAC tests."""
    
    def test_poly1305_basic(self):
        """Test Poly1305 produces 16-byte tag."""
        from ewsp_core import poly1305
        
        key = bytes(32)
        data = b"test message"
        
        tag = poly1305(key, data)
        assert len(tag) == 16
    
    def test_poly1305_different_messages(self):
        """Test Poly1305 produces different tags for different messages."""
        from ewsp_core import poly1305
        
        key = bytes(32)
        
        tag1 = poly1305(key, b"message 1")
        tag2 = poly1305(key, b"message 2")
        
        assert tag1 != tag2
    
    def test_poly1305_invalid_key(self):
        """Test Poly1305 rejects invalid key."""
        from ewsp_core import poly1305
        
        with pytest.raises(ValueError, match="Key must be 32 bytes"):
            poly1305(b"short", b"data")


class TestAEAD:
    """XChaCha20-Poly1305 AEAD tests."""
    
    def test_aead_roundtrip(self):
        """Test AEAD encrypt/decrypt roundtrip."""
        from ewsp_core import aead_encrypt, aead_decrypt
        
        key = bytes(32)
        nonce = bytes(24)
        plaintext = b"Hello, AEAD!"
        ad = b"associated data"
        
        ciphertext = aead_encrypt(key, nonce, plaintext, ad)
        decrypted = aead_decrypt(key, nonce, ciphertext, ad)
        
        assert decrypted == plaintext
        assert len(ciphertext) == len(plaintext) + 16
    
    def test_aead_no_ad(self):
        """Test AEAD with no associated data."""
        from ewsp_core import aead_encrypt, aead_decrypt
        
        key = bytes(32)
        nonce = bytes(24)
        plaintext = b"No AD test"
        
        ciphertext = aead_encrypt(key, nonce, plaintext)
        decrypted = aead_decrypt(key, nonce, ciphertext)
        
        assert decrypted == plaintext
    
    def test_aead_tampered_ciphertext(self):
        """Test AEAD rejects tampered ciphertext."""
        from ewsp_core import aead_encrypt, aead_decrypt, EwspException
        
        key = bytes(32)
        nonce = bytes(24)
        plaintext = b"Do not tamper!"
        
        ciphertext = aead_encrypt(key, nonce, plaintext)
        
        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        tampered = bytes(tampered)
        
        with pytest.raises((EwspException, ValueError)):
            aead_decrypt(key, nonce, tampered)
    
    def test_aead_wrong_ad(self):
        """Test AEAD rejects wrong associated data."""
        from ewsp_core import aead_encrypt, aead_decrypt, EwspException
        
        key = bytes(32)
        nonce = bytes(24)
        plaintext = b"AD must match!"
        ad = b"correct AD"
        
        ciphertext = aead_encrypt(key, nonce, plaintext, ad)
        
        with pytest.raises((EwspException, ValueError)):
            aead_decrypt(key, nonce, ciphertext, b"wrong AD")


class TestCryptoManager:
    """CryptoManager high-level API tests."""
    
    def test_crypto_manager_init(self):
        """Test CryptoManager initialization."""
        from ewsp_core import CryptoManager
        
        token = "a" * 32
        crypto = CryptoManager(token)
        assert crypto is not None
    
    def test_crypto_manager_short_token(self):
        """Test CryptoManager rejects short token."""
        from ewsp_core import CryptoManager
        
        with pytest.raises(ValueError, match="at least 32 characters"):
            CryptoManager("short")
    
    def test_crypto_manager_encrypt_decrypt(self):
        """Test CryptoManager encrypt/decrypt roundtrip."""
        from ewsp_core import CryptoManager
        
        token = "test_token_32_characters_long!!!"
        crypto = CryptoManager(token)
        
        original = b"Hello, CryptoManager!"
        encrypted = crypto.encrypt(original)
        decrypted = crypto.decrypt(encrypted)
        
        assert decrypted == original
        assert isinstance(encrypted, str)  # Hex string
    
    def test_crypto_manager_sign_verify(self):
        """Test CryptoManager sign/verify."""
        from ewsp_core import CryptoManager
        
        token = "test_token_32_characters_long!!!"
        crypto = CryptoManager(token)
        
        data = b"data to sign"
        signature = crypto.sign(data)
        
        assert crypto.verify(data, signature)
        assert not crypto.verify(data, "0" * 64)
    
    def test_crypto_manager_aead(self):
        """Test CryptoManager AEAD methods."""
        from ewsp_core import CryptoManager
        
        token = "test_token_32_characters_long!!!"
        crypto = CryptoManager(token)
        
        plaintext = b"AEAD test message"
        ad = b"header data"
        
        ciphertext, nonce = crypto.aead_encrypt(plaintext, ad)
        decrypted = crypto.aead_decrypt(ciphertext, nonce, ad)
        
        assert decrypted == plaintext


class TestPacketManager:
    """PacketManager high-level API tests."""
    
    def test_packet_manager_create_command(self):
        """Test PacketManager command creation."""
        from ewsp_core import PacketManager
        import json
        
        token = "test_token_32_characters_long!!!"
        device_id = "device123"
        
        pm = PacketManager(token, device_id)
        packet = pm.create_command("ping")
        
        # Should be valid JSON
        parsed = json.loads(packet)
        assert parsed["device_id"] == device_id
        assert "payload" in parsed
        assert "signature" in parsed
        assert parsed["version"] == "1.0"
    
    def test_packet_manager_chain(self):
        """Test PacketManager blockchain chaining."""
        from ewsp_core import PacketManager
        import json
        
        token = "test_token_32_characters_long!!!"
        device_id = "device123"
        
        pm = PacketManager(token, device_id)
        
        p1 = json.loads(pm.create_command("ping"))
        p2 = json.loads(pm.create_command("info"))
        
        assert p1["request_counter"] == 1
        assert p2["request_counter"] == 2
        assert p1["chain_hash"] != p2["chain_hash"]
    
    def test_packet_manager_state_export_import(self):
        """Test PacketManager state persistence."""
        from ewsp_core import PacketManager
        
        token = "test_token_32_characters_long!!!"
        device_id = "device123"
        
        pm1 = PacketManager(token, device_id)
        pm1.create_command("test")
        pm1.create_command("test")
        
        state = pm1.export_state()
        
        pm2 = PacketManager(token, device_id)
        pm2.import_state(state)
        
        assert pm2.export_state().tx_sequence == 2


class TestUtilities:
    """Utility function tests."""
    
    def test_constant_time_compare_equal(self):
        """Test constant_time_compare with equal values."""
        from ewsp_core import constant_time_compare
        
        a = b"test data"
        assert constant_time_compare(a, a) is True
    
    def test_constant_time_compare_different(self):
        """Test constant_time_compare with different values."""
        from ewsp_core import constant_time_compare
        
        a = b"test data"
        b = b"TEST DATA"
        assert constant_time_compare(a, b) is False
    
    def test_constant_time_compare_length(self):
        """Test constant_time_compare with different lengths."""
        from ewsp_core import constant_time_compare
        
        assert constant_time_compare(b"short", b"longer value") is False
    
    def test_random_bytes(self):
        """Test random_bytes generation."""
        from ewsp_core import random_bytes
        
        r1 = random_bytes(32)
        r2 = random_bytes(32)
        
        assert len(r1) == 32
        assert len(r2) == 32
        assert r1 != r2  # Astronomically unlikely to be equal
    
    def test_hex_conversion(self):
        """Test hex conversion utilities."""
        from ewsp_core import bytes_to_hex, hex_to_bytes
        
        original = b"\x00\x11\x22\xff"
        hex_str = bytes_to_hex(original)
        recovered = hex_to_bytes(hex_str)
        
        assert hex_str == "001122ff"
        assert recovered == original


class TestVersionInfo:
    """Version information tests."""
    
    def test_get_version(self):
        """Test get_version returns string."""
        from ewsp_core import get_version
        
        version = get_version()
        assert isinstance(version, str)
        assert "2" in version  # Should be version 2.x
    
    def test_get_protocol_version(self):
        """Test get_protocol_version returns string."""
        from ewsp_core import get_protocol_version
        
        protocol = get_protocol_version()
        assert isinstance(protocol, str)
        assert "2" in protocol
    
    def test_is_native(self):
        """Test is_native returns boolean."""
        from ewsp_core import is_native
        
        result = is_native()
        assert isinstance(result, bool)
        # Both values are valid - depends on C library availability


class TestFallback:
    """Pure Python fallback tests."""
    
    def test_pure_python_sha256(self):
        """Test pure Python SHA-256 directly."""
        from crypto_pure import sha256
        
        result = sha256(b"abc")
        expected = bytes.fromhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        assert result == expected
    
    def test_pure_python_xchacha20(self):
        """Test pure Python XChaCha20 directly."""
        from crypto_pure import xchacha20_encrypt, xchacha20_decrypt
        
        key = bytes(32)
        nonce = bytes(24)
        plaintext = b"Test message"
        
        ciphertext = xchacha20_encrypt(key, nonce, plaintext)
        decrypted = xchacha20_decrypt(key, nonce, ciphertext)
        
        assert decrypted == plaintext
    
    def test_pure_python_aead(self):
        """Test pure Python AEAD directly."""
        from crypto_pure import aead_encrypt, aead_decrypt
        
        key = bytes(32)
        nonce = bytes(24)
        plaintext = b"AEAD fallback test"
        ad = b"additional data"
        
        ciphertext = aead_encrypt(key, nonce, plaintext, ad)
        decrypted = aead_decrypt(key, nonce, ciphertext, ad)
        
        assert decrypted == plaintext


class TestErrorHandling:
    """Error handling tests."""
    
    def test_ewsp_error_enum(self):
        """Test EwspError enum values."""
        from ewsp_core import EwspError
        
        assert EwspError.OK == 0
        assert EwspError.AUTH_FAILED == 13
        assert EwspError.REPLAY_DETECTED == 23
    
    def test_ewsp_exception(self):
        """Test EwspException."""
        from ewsp_core import EwspError, EwspException
        
        exc = EwspException(EwspError.AUTH_FAILED, "Test error")
        assert exc.code == EwspError.AUTH_FAILED
        assert "Test error" in str(exc)


# ============================================================================
# Run tests directly
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
