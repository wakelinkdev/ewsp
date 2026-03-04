/**
 * EWSP Core - Unified Crypto Interface
 * 
 * Single entry point for all cryptographic operations.
 * Automatically selects native (JNI) or pure Kotlin implementation.
 * 
 * Location: ewsp-core/bindings/kotlin/
 * 
 * Usage: 
 *   val crypto = Crypto.create(token)
 *   val encrypted = crypto.createSecurePayload("hello")
 *   
 *   // AEAD encryption
 *   val result = Crypto.aeadEncrypt(key, nonce, plaintext, ad)
 *   val decrypted = Crypto.aeadDecrypt(key, nonce, ciphertext, ad)
 * 
 * @version 1.0.0
 * @since 2026-02-08
 */
package org.wakelink.ewsp

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Unified crypto interface that automatically selects best implementation.
 */
interface ICrypto {
    fun calculateHmac(data: String): String
    fun verifyHmac(data: String, signature: String): Boolean
    fun createSecurePayload(plaintext: String): String
    fun decryptPayload(hexPayload: String): Result<String>
    
    // AEAD methods
    fun aeadEncrypt(plaintext: ByteArray, ad: ByteArray? = null): AeadResult
    fun aeadDecrypt(ciphertext: ByteArray, nonce: ByteArray, ad: ByteArray? = null): Result<ByteArray>
}

/**
 * AEAD encryption result containing ciphertext and nonce.
 */
data class AeadResult(
    val ciphertext: ByteArray,
    val nonce: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AeadResult) return false
        return ciphertext.contentEquals(other.ciphertext) && nonce.contentEquals(other.nonce)
    }
    
    override fun hashCode(): Int = 31 * ciphertext.contentHashCode() + nonce.contentHashCode()
}

/**
 * Factory for creating crypto instances.
 */
object Crypto {
    
    // ==================== Configuration ====================
    
    const val NONCE_SIZE = 24
    const val KEY_SIZE = 32
    const val HMAC_SIZE = 32
    const val AEAD_TAG_SIZE = 16
    const val VERSION = "1.0.0"
    const val PROTOCOL_VERSION = "1.0"
    
    /**
     * Check if native library is available.
     */
    fun isNativeAvailable(): Boolean = CryptoNative.isNativeAvailable()
    
    /**
     * Create crypto instance with automatic implementation selection.
     * Uses native JNI if available, otherwise pure Kotlin.
     */
    fun create(token: String): ICrypto {
        return if (isNativeAvailable()) {
            CryptoNativeWrapper(token)
        } else {
            CryptoPureWrapper(token)
        }
    }
    
    // ==================== Static Utilities ====================
    
    /**
     * SHA-256 hash.
     */
    fun sha256(data: ByteArray): ByteArray {
        return if (isNativeAvailable()) {
            CryptoNative.sha256(data)
        } else {
            MessageDigest.getInstance("SHA-256").digest(data)
        }
    }
    
    /**
     * HMAC-SHA256.
     */
    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        return if (isNativeAvailable()) {
            CryptoNative.hmacSha256(key, data)
        } else {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(key, "HmacSHA256"))
            mac.doFinal(data)
        }
    }
    
    /**
     * HMAC-SHA256 verification (constant-time).
     */
    fun hmacVerify(mac1: ByteArray, mac2: ByteArray): Boolean {
        if (mac1.size != 32 || mac2.size != 32) return false
        return if (isNativeAvailable()) {
            CryptoNative.hmacVerify(mac1, mac2)
        } else {
            constantTimeEquals(mac1, mac2)
        }
    }
    
    /**
     * HKDF-SHA256 key derivation.
     */
    fun hkdf(ikm: ByteArray, info: ByteArray, length: Int = KEY_SIZE): ByteArray {
        return if (isNativeAvailable()) {
            CryptoNative.hkdf(null, ikm, info, length)
        } else {
            CryptoPure.hkdf(ikm, info, length)
        }
    }
    
    /**
     * XChaCha20 encryption/decryption.
     */
    fun xchacha20(key: ByteArray, nonce: ByteArray, data: ByteArray): ByteArray {
        require(key.size == 32) { "Key must be 32 bytes" }
        require(nonce.size >= 24) { "Nonce must be at least 24 bytes" }
        return if (isNativeAvailable()) {
            CryptoNative.xchacha20(key, nonce, data)
        } else {
            CryptoPure.xchacha20(key, nonce, data)
        }
    }
    
    /**
     * Poly1305 MAC.
     */
    fun poly1305(key: ByteArray, data: ByteArray): ByteArray {
        require(key.size == 32) { "Key must be 32 bytes" }
        return if (isNativeAvailable()) {
            CryptoNative.poly1305(key, data)
        } else {
            CryptoPure.poly1305(key, data)
        }
    }
    
    /**
     * XChaCha20-Poly1305 AEAD encryption.
     * @param key 32-byte encryption key.
     * @param nonce 24-byte nonce.
     * @param plaintext Data to encrypt.
     * @param ad Associated data (authenticated but not encrypted).
     * @return Ciphertext with 16-byte tag appended.
     */
    fun aeadEncrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, ad: ByteArray? = null): ByteArray {
        require(key.size == 32) { "Key must be 32 bytes" }
        require(nonce.size >= 24) { "Nonce must be at least 24 bytes" }
        return if (isNativeAvailable()) {
            CryptoNative.aeadEncrypt(key, nonce, plaintext, ad)
        } else {
            CryptoPure.aeadEncrypt(key, nonce, plaintext, ad)
        }
    }
    
    /**
     * XChaCha20-Poly1305 AEAD decryption.
     * @param key 32-byte encryption key.
     * @param nonce 24-byte nonce.
     * @param ciphertext Ciphertext with 16-byte tag.
     * @param ad Associated data (must match encryption).
     * @return Decrypted plaintext, or null if authentication fails.
     */
    fun aeadDecrypt(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, ad: ByteArray? = null): ByteArray? {
        require(key.size == 32) { "Key must be 32 bytes" }
        require(nonce.size >= 24) { "Nonce must be at least 24 bytes" }
        require(ciphertext.size >= 16) { "Ciphertext must include 16-byte tag" }
        return if (isNativeAvailable()) {
            CryptoNative.aeadDecrypt(key, nonce, ciphertext, ad)
        } else {
            CryptoPure.aeadDecrypt(key, nonce, ciphertext, ad)
        }
    }
    
    /**
     * Generate random bytes.
     */
    fun randomBytes(size: Int): ByteArray {
        return if (isNativeAvailable()) {
            CryptoNative.randomBytes(size)
        } else {
            CryptoPure.randomBytes(size)
        }
    }
    
    /**
     * Constant-time comparison.
     */
    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        return if (isNativeAvailable()) {
            CryptoNative.constantTimeCompare(a, b)
        } else {
            CryptoPure.constantTimeEquals(a, b)
        }
    }
    
    // ==================== Hex Utilities ====================
    
    fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
    
    fun String.hexToByteArray(): ByteArray {
        val len = length
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            data[i / 2] = ((Character.digit(this[i], 16) shl 4) + Character.digit(this[i + 1], 16)).toByte()
            i += 2
        }
        return data
    }
}

/**
 * Native JNI implementation wrapper.
 */
internal class CryptoNativeWrapper(token: String) : ICrypto {
    
    private val chachaKey: ByteArray
    private val hmacKey: ByteArray
    
    init {
        require(token.length >= 32) { "Token must be ≥32 characters" }
        
        val tokenBytes = token.toByteArray(Charsets.UTF_8)
        val masterKey = CryptoNative.sha256(tokenBytes)
        
        // Key separation using HKDF
        chachaKey = CryptoNative.hkdf(null, masterKey, "wakelink_encryption_v2".toByteArray(), 32)
        hmacKey = CryptoNative.hkdf(null, masterKey, "wakelink_authentication_v2".toByteArray(), 32)
    }
    
    override fun calculateHmac(data: String): String {
        return CryptoNative.hmacSha256(hmacKey, data.toByteArray(Charsets.UTF_8)).let {
            Crypto.run { it.toHex() }
        }
    }
    
    override fun verifyHmac(data: String, signature: String): Boolean {
        val expected = CryptoNative.hmacSha256(hmacKey, data.toByteArray(Charsets.UTF_8))
        val received = try {
            Crypto.run { signature.lowercase().hexToByteArray() }
        } catch (e: Exception) {
            return false
        }
        return CryptoNative.constantTimeCompare(expected, received)
    }
    
    override fun createSecurePayload(plaintext: String): String {
        val data = plaintext.toByteArray(Charsets.UTF_8).let {
            if (it.size > 500) it.copyOf(500) else it
        }
        val nonce = CryptoNative.randomBytes(Crypto.NONCE_SIZE)
        val cipher = CryptoNative.xchacha20(chachaKey, nonce, data)
        
        val packet = ByteBuffer.allocate(2 + cipher.size + Crypto.NONCE_SIZE)
            .order(ByteOrder.BIG_ENDIAN)
            .putShort(data.size.toShort())
            .put(cipher)
            .put(nonce)
            .array()
        
        return Crypto.run { packet.toHex() }
    }
    
    override fun decryptPayload(hexPayload: String): Result<String> {
        return try {
            val packet = Crypto.run { hexPayload.hexToByteArray() }
            
            if (packet.size < 26) {
                return Result.failure(Exception("Packet too short"))
            }
            
            val length = ByteBuffer.wrap(packet, 0, 2).order(ByteOrder.BIG_ENDIAN).short.toInt() and 0xFFFF
            
            if (length > 500 || packet.size < 2 + length + Crypto.NONCE_SIZE) {
                return Result.failure(Exception("Invalid packet size"))
            }
            
            val cipher = packet.copyOfRange(2, 2 + length)
            val nonce = packet.copyOfRange(packet.size - Crypto.NONCE_SIZE, packet.size)
            
            val plainBytes = CryptoNative.xchacha20(chachaKey, nonce, cipher)
            Result.success(String(plainBytes, Charsets.UTF_8))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    override fun aeadEncrypt(plaintext: ByteArray, ad: ByteArray?): AeadResult {
        val nonce = CryptoNative.randomBytes(Crypto.NONCE_SIZE)
        val ciphertext = CryptoNative.aeadEncrypt(chachaKey, nonce, plaintext, ad)
        return AeadResult(ciphertext, nonce)
    }
    
    override fun aeadDecrypt(ciphertext: ByteArray, nonce: ByteArray, ad: ByteArray?): Result<ByteArray> {
        return try {
            val plaintext = CryptoNative.aeadDecrypt(chachaKey, nonce, ciphertext, ad)
            if (plaintext != null) {
                Result.success(plaintext)
            } else {
                Result.failure(SecurityException("AEAD authentication failed"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}

/**
 * Pure Kotlin implementation wrapper.
 */
internal class CryptoPureWrapper(token: String) : ICrypto {
    
    private val crypto = CryptoPure(token)
    
    override fun calculateHmac(data: String): String = crypto.calculateHmac(data)
    override fun verifyHmac(data: String, signature: String): Boolean = crypto.verifyHmac(data, signature)
    override fun createSecurePayload(plaintext: String): String = crypto.createSecurePayload(plaintext)
    override fun decryptPayload(hexPayload: String): Result<String> = crypto.decryptPayload(hexPayload)
    
    override fun aeadEncrypt(plaintext: ByteArray, ad: ByteArray?): AeadResult {
        val nonce = CryptoPure.randomBytes(Crypto.NONCE_SIZE)
        val ciphertext = CryptoPure.aeadEncrypt(crypto.chachaKey, nonce, plaintext, ad)
        return AeadResult(ciphertext, nonce)
    }
    
    override fun aeadDecrypt(ciphertext: ByteArray, nonce: ByteArray, ad: ByteArray?): Result<ByteArray> {
        return try {
            val plaintext = CryptoPure.aeadDecrypt(crypto.chachaKey, nonce, ciphertext, ad)
            if (plaintext != null) {
                Result.success(plaintext)
            } else {
                Result.failure(SecurityException("AEAD authentication failed"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
