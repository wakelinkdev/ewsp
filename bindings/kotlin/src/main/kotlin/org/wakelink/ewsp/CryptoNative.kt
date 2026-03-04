/**
 * EWSP Core - Kotlin/JNI Native Binding
 * 
 * JNI binding to ewsp-core C library for optimal performance.
 * Falls back to CryptoPure when native library is not available.
 * 
 * Location: ewsp-core/bindings/kotlin/
 * 
 * Build native library:
 *   cd ewsp-core/bindings/kotlin/jni
 *   cmake -B build && cmake --build build
 * 
 * For Android, use Android Studio's native build integration or:
 *   cmake -B build-android \
 *     -DANDROID_ABI=arm64-v8a \
 *     -DANDROID_PLATFORM=android-21 \
 *     -DCMAKE_TOOLCHAIN_FILE=$NDK_HOME/build/cmake/android.toolchain.cmake
 *   cmake --build build-android
 * 
 * @version 1.0.0
 * @since 2026-02-08
 */
package org.wakelink.ewsp

/**
 * JNI Native binding to ewsp-core C library.
 * 
 * This class loads the native ewsp_core library and provides direct access
 * to C cryptographic functions for maximum performance.
 */
object CryptoNative {
    
    private var nativeLoaded = false
    
    init {
        nativeLoaded = try {
            System.loadLibrary("ewsp_core")
            true
        } catch (e: UnsatisfiedLinkError) {
            false
        }
    }
    
    /**
     * Check if native library is loaded.
     */
    fun isNativeAvailable(): Boolean = nativeLoaded
    
    // ==================== SHA-256 ====================
    
    /**
     * SHA-256 hash function.
     * @param data Input data to hash.
     * @return 32-byte hash.
     */
    external fun sha256(data: ByteArray): ByteArray
    
    // ==================== HMAC-SHA256 ====================
    
    /**
     * HMAC-SHA256 keyed hash.
     * @param key Authentication key.
     * @param data Data to authenticate.
     * @return 32-byte MAC.
     */
    external fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray
    
    /**
     * Constant-time HMAC verification.
     * @param mac1 First MAC to compare.
     * @param mac2 Second MAC to compare.
     * @return true if MACs are equal.
     */
    external fun hmacVerify(mac1: ByteArray, mac2: ByteArray): Boolean
    
    // ==================== HKDF-SHA256 ====================
    
    /**
     * HKDF-SHA256 key derivation (RFC 5869).
     * @param salt Optional salt (can be null).
     * @param ikm Input keying material.
     * @param info Context/application-specific info.
     * @param length Desired output length in bytes.
     * @return Derived key material.
     */
    external fun hkdf(salt: ByteArray?, ikm: ByteArray, info: ByteArray, length: Int): ByteArray
    
    // ==================== XChaCha20 ====================
    
    /**
     * XChaCha20 encryption/decryption (symmetric).
     * @param key 32-byte encryption key.
     * @param nonce 24-byte nonce.
     * @param data Data to encrypt/decrypt.
     * @return Encrypted/decrypted data.
     */
    external fun xchacha20(key: ByteArray, nonce: ByteArray, data: ByteArray): ByteArray
    
    // ==================== Poly1305 ====================
    
    /**
     * Poly1305 one-time MAC.
     * @param key 32-byte one-time key (MUST be unique per message).
     * @param data Data to authenticate.
     * @return 16-byte authentication tag.
     */
    external fun poly1305(key: ByteArray, data: ByteArray): ByteArray
    
    // ==================== XChaCha20-Poly1305 AEAD ====================
    
    /**
     * XChaCha20-Poly1305 authenticated encryption.
     * @param key 32-byte encryption key.
     * @param nonce 24-byte nonce (MUST be unique per key).
     * @param plaintext Data to encrypt.
     * @param ad Associated data (authenticated but not encrypted), can be null.
     * @return Ciphertext with 16-byte authentication tag appended.
     */
    external fun aeadEncrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, ad: ByteArray?): ByteArray
    
    /**
     * XChaCha20-Poly1305 authenticated decryption.
     * @param key 32-byte encryption key.
     * @param nonce 24-byte nonce (same as used for encryption).
     * @param ciphertext Ciphertext with 16-byte tag appended.
     * @param ad Associated data (must match encryption), can be null.
     * @return Decrypted plaintext, or null if authentication fails.
     */
    external fun aeadDecrypt(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, ad: ByteArray?): ByteArray?
    
    // ==================== Utility Functions ====================
    
    /**
     * Generate cryptographically secure random bytes.
     * @param size Number of bytes to generate.
     * @return Random bytes.
     */
    external fun randomBytes(size: Int): ByteArray
    
    /**
     * Constant-time byte comparison.
     * @param a First array.
     * @param b Second array.
     * @return true if arrays are equal.
     */
    external fun constantTimeCompare(a: ByteArray, b: ByteArray): Boolean
    
    // ==================== Version Info ====================
    
    /**
     * Library version.
     * @return Version string (e.g., "1.0.0").
     */
    external fun version(): String
    
    /**
     * Protocol version.
     * @return Protocol version string (e.g., "1.0").
     */
    external fun protocolVersion(): String
}
