/**
 * EWSP Core - Kotlin Binding Unit Tests
 * 
 * Tests for cryptographic operations: SHA256, HMAC, HKDF, XChaCha20, Poly1305, AEAD.
 * Uses pure Kotlin implementation (CryptoPure) for JVM testing.
 * Test vectors compatible with Python binding tests.
 * 
 * @author deadboizxc
 * @version 1.0.0
 */
package org.wakelink.ewsp

import kotlin.test.*

class CryptoTest {
    
    // ============================================================================
    // SHA-256 Tests
    // ============================================================================
    
    @Test
    fun `SHA256 empty string`() {
        val hash = CryptoPure.sha256(ByteArray(0))
        val expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assertEquals(expected, hash.toHex())
    }
    
    @Test
    fun `SHA256 hello world`() {
        val hash = CryptoPure.sha256("hello".toByteArray(Charsets.UTF_8))
        val expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        assertEquals(expected, hash.toHex())
    }
    
    @Test
    fun `SHA256 deterministic`() {
        val data = "test data for sha256".toByteArray(Charsets.UTF_8)
        val hash1 = CryptoPure.sha256(data)
        val hash2 = CryptoPure.sha256(data)
        assertContentEquals(hash1, hash2)
    }
    
    // ============================================================================
    // HMAC-SHA256 Tests
    // ============================================================================
    
    @Test
    fun `HMAC basic`() {
        val key = ByteArray(32) { it.toByte() }
        val data = "Hello, World!".toByteArray(Charsets.UTF_8)
        val hmac = CryptoPure.hmacSha256(key, data)
        assertEquals(32, hmac.size)
    }
    
    @Test
    fun `HMAC deterministic`() {
        val key = ByteArray(32) { it.toByte() }
        val data = "test data".toByteArray(Charsets.UTF_8)
        val hmac1 = CryptoPure.hmacSha256(key, data)
        val hmac2 = CryptoPure.hmacSha256(key, data)
        assertContentEquals(hmac1, hmac2)
    }
    
    @Test
    fun `HMAC different keys produce different results`() {
        val key1 = ByteArray(32) { 0x01.toByte() }
        val key2 = ByteArray(32) { 0x02.toByte() }
        val data = "test data".toByteArray(Charsets.UTF_8)
        val hmac1 = CryptoPure.hmacSha256(key1, data)
        val hmac2 = CryptoPure.hmacSha256(key2, data)
        assertFalse(hmac1.contentEquals(hmac2))
    }
    
    // ============================================================================
    // HKDF Tests
    // ============================================================================
    
    @Test
    fun `HKDF derives correct length`() {
        val ikm = ByteArray(32) { it.toByte() }
        val info = "test info".toByteArray(Charsets.UTF_8)
        val derived = CryptoPure.hkdf(ikm, info, 32)
        assertEquals(32, derived.size)
    }
    
    @Test
    fun `HKDF different info produces different keys`() {
        val ikm = ByteArray(32) { it.toByte() }
        val key1 = CryptoPure.hkdf(ikm, "encryption".toByteArray(Charsets.UTF_8), 32)
        val key2 = CryptoPure.hkdf(ikm, "authentication".toByteArray(Charsets.UTF_8), 32)
        assertFalse(key1.contentEquals(key2))
    }
    
    @Test
    fun `HKDF deterministic`() {
        val ikm = ByteArray(32) { it.toByte() }
        val info = "test".toByteArray(Charsets.UTF_8)
        val key1 = CryptoPure.hkdf(ikm, info, 32)
        val key2 = CryptoPure.hkdf(ikm, info, 32)
        assertContentEquals(key1, key2)
    }
    
    // ============================================================================
    // XChaCha20 Tests
    // ============================================================================
    
    @Test
    fun `XChaCha20 roundtrip`() {
        val key = ByteArray(32) { it.toByte() }
        val nonce = ByteArray(24) { (it * 2).toByte() }
        val plaintext = "Hello, XChaCha20!".toByteArray(Charsets.UTF_8)
        
        val ciphertext = CryptoPure.xchacha20(key, nonce, plaintext)
        val decrypted = CryptoPure.xchacha20(key, nonce, ciphertext)
        
        assertContentEquals(plaintext, decrypted)
    }
    
    @Test
    fun `XChaCha20 different nonces produce different ciphertexts`() {
        val key = ByteArray(32) { it.toByte() }
        val nonce1 = ByteArray(24) { 0x01.toByte() }
        val nonce2 = ByteArray(24) { 0x02.toByte() }
        val plaintext = "test".toByteArray(Charsets.UTF_8)
        
        val ct1 = CryptoPure.xchacha20(key, nonce1, plaintext)
        val ct2 = CryptoPure.xchacha20(key, nonce2, plaintext)
        
        assertFalse(ct1.contentEquals(ct2))
    }
    
    @Test
    fun `XChaCha20 ciphertext same length as plaintext`() {
        val key = ByteArray(32) { it.toByte() }
        val nonce = ByteArray(24) { it.toByte() }
        val plaintext = "variable length plaintext".toByteArray(Charsets.UTF_8)
        
        val ciphertext = CryptoPure.xchacha20(key, nonce, plaintext)
        assertEquals(plaintext.size, ciphertext.size)
    }
    
    // ============================================================================
    // Poly1305 Tests
    // ============================================================================
    
    @Test
    fun `Poly1305 MAC length is 16 bytes`() {
        val key = ByteArray(32) { it.toByte() }
        val data = "test message".toByteArray(Charsets.UTF_8)
        val mac = CryptoPure.poly1305(key, data)
        assertEquals(16, mac.size)
    }
    
    @Test
    fun `Poly1305 different messages produce different MACs`() {
        val key = ByteArray(32) { it.toByte() }
        val mac1 = CryptoPure.poly1305(key, "message1".toByteArray(Charsets.UTF_8))
        val mac2 = CryptoPure.poly1305(key, "message2".toByteArray(Charsets.UTF_8))
        assertFalse(mac1.contentEquals(mac2))
    }
    
    @Test
    fun `Poly1305 deterministic`() {
        val key = ByteArray(32) { it.toByte() }
        val data = "test".toByteArray(Charsets.UTF_8)
        val mac1 = CryptoPure.poly1305(key, data)
        val mac2 = CryptoPure.poly1305(key, data)
        assertContentEquals(mac1, mac2)
    }
    
    // ============================================================================
    // AEAD (XChaCha20-Poly1305) Tests
    // ============================================================================
    
    @Test
    fun `AEAD roundtrip`() {
        val key = ByteArray(32) { it.toByte() }
        val nonce = ByteArray(24) { (it * 3).toByte() }
        val plaintext = "Secret message!".toByteArray(Charsets.UTF_8)
        val ad = "associated data".toByteArray(Charsets.UTF_8)
        
        val ciphertext = CryptoPure.aeadEncrypt(key, nonce, plaintext, ad)
        val decrypted = CryptoPure.aeadDecrypt(key, nonce, ciphertext, ad)
        
        assertNotNull(decrypted)
        assertContentEquals(plaintext, decrypted)
    }
    
    @Test
    fun `AEAD without associated data`() {
        val key = ByteArray(32) { it.toByte() }
        val nonce = ByteArray(24) { it.toByte() }
        val plaintext = "No AD".toByteArray(Charsets.UTF_8)
        
        val ciphertext = CryptoPure.aeadEncrypt(key, nonce, plaintext, null)
        val decrypted = CryptoPure.aeadDecrypt(key, nonce, ciphertext, null)
        
        assertNotNull(decrypted)
        assertContentEquals(plaintext, decrypted)
    }
    
    @Test
    fun `AEAD ciphertext is plaintext + 16 bytes tag`() {
        val key = ByteArray(32) { it.toByte() }
        val nonce = ByteArray(24) { it.toByte() }
        val plaintext = "test plaintext".toByteArray(Charsets.UTF_8)
        
        val ciphertext = CryptoPure.aeadEncrypt(key, nonce, plaintext, null)
        assertEquals(plaintext.size + 16, ciphertext.size)
    }
    
    @Test
    fun `AEAD detects tampered ciphertext`() {
        val key = ByteArray(32) { it.toByte() }
        val nonce = ByteArray(24) { it.toByte() }
        val plaintext = "secret".toByteArray(Charsets.UTF_8)
        val ad = "ad".toByteArray(Charsets.UTF_8)
        
        val ciphertext = CryptoPure.aeadEncrypt(key, nonce, plaintext, ad)
        
        // Tamper with ciphertext
        val tampered = ciphertext.copyOf()
        tampered[0] = (tampered[0].toInt() xor 0xFF).toByte()
        
        val decrypted = CryptoPure.aeadDecrypt(key, nonce, tampered, ad)
        assertNull(decrypted, "Decryption should fail for tampered ciphertext")
    }
    
    @Test
    fun `AEAD detects wrong associated data`() {
        val key = ByteArray(32) { it.toByte() }
        val nonce = ByteArray(24) { it.toByte() }
        val plaintext = "secret".toByteArray(Charsets.UTF_8)
        val ad1 = "correct AD".toByteArray(Charsets.UTF_8)
        val ad2 = "wrong AD".toByteArray(Charsets.UTF_8)
        
        val ciphertext = CryptoPure.aeadEncrypt(key, nonce, plaintext, ad1)
        val decrypted = CryptoPure.aeadDecrypt(key, nonce, ciphertext, ad2)
        
        assertNull(decrypted, "Decryption should fail for wrong AD")
    }
    
    @Test
    fun `AEAD empty plaintext`() {
        val key = ByteArray(32) { it.toByte() }
        val nonce = ByteArray(24) { it.toByte() }
        val plaintext = ByteArray(0)
        
        val ciphertext = CryptoPure.aeadEncrypt(key, nonce, plaintext, null)
        assertEquals(16, ciphertext.size) // Only tag
        
        val decrypted = CryptoPure.aeadDecrypt(key, nonce, ciphertext, null)
        assertNotNull(decrypted)
        assertEquals(0, decrypted.size)
    }
    
    // ============================================================================
    // CryptoManager Integration Tests
    // ============================================================================
    
    @Test
    fun `CryptoManager encrypt decrypt roundtrip`() {
        val token = "a".repeat(32)  // 32-char token
        val crypto = CryptoPure(token)
        
        val plaintext = "Hello, WakeLink!"
        val payload = crypto.createSecurePayload(plaintext)
        val decrypted = crypto.decryptPayload(payload)
        
        assertTrue(decrypted.isSuccess)
        assertEquals(plaintext, decrypted.getOrThrow())
    }
    
    @Test
    fun `CryptoManager HMAC sign and verify`() {
        val token = "b".repeat(32)
        val crypto = CryptoPure(token)
        
        val data = "test|data|123"
        val signature = crypto.calculateHmac(data)
        
        assertTrue(crypto.verifyHmac(data, signature))
        assertFalse(crypto.verifyHmac(data, "invalid_signature"))
    }
    
    @Test
    fun `CryptoManager AEAD roundtrip`() {
        val token = "c".repeat(32)
        val crypto = CryptoPure(token)
        
        val plaintext = "AEAD test message".toByteArray(Charsets.UTF_8)
        val ad = "header".toByteArray(Charsets.UTF_8)
        
        val result = crypto.aeadEncrypt(plaintext, ad)
        val decrypted = crypto.aeadDecrypt(result.ciphertext, result.nonce, ad)
        
        assertTrue(decrypted.isSuccess)
        assertContentEquals(plaintext, decrypted.getOrThrow())
    }
    
    // ============================================================================
    // Utility Extension
    // ============================================================================
    
    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xFF) }
}
