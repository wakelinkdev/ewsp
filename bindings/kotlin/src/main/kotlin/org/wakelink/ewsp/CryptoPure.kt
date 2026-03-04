/**
 * EWSP Core - Kotlin Pure Implementation (Fallback)
 * 
 * This is a FALLBACK implementation for platforms where ewsp-core JNI binding
 * is not available. The primary source of truth for crypto is ewsp-core C library.
 * 
 * Location: ewsp-core/bindings/kotlin/
 * Usage: Used by wakelink-android and wakelink-multiplatform when JNI unavailable
 * 
 * @version 1.0.0
 * @since 2026-02-08
 */
package org.wakelink.ewsp

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.xor

/**
 * Pure Kotlin/JVM implementation of EWSP cryptographic primitives.
 * 
 * Implements:
 * - SHA-256 (via JVM)
 * - HMAC-SHA256 (via JVM)
 * - HKDF-SHA256 (RFC 5869)
 * - ChaCha20 (RFC 7539)
 * - XChaCha20 (24-byte nonce variant)
 * - Poly1305 MAC (RFC 7539)
 * - XChaCha20-Poly1305 AEAD
 * 
 * Security features (v1.0):
 * - Key separation using HKDF
 * - Constant-time comparison
 * - Hardware RNG (SecureRandom)
 */
class CryptoPure(token: String) {
    
    companion object {
        const val NONCE_SIZE = 24
        const val KEY_SIZE = 32
        const val HMAC_SIZE = 32
        const val AEAD_TAG_SIZE = 16
        
        // ChaCha20 constants ("expand 32-byte k")
        private val CHACHA_CONSTANTS = intArrayOf(0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)
        
        /**
         * Generate cryptographically secure random bytes.
         */
        fun randomBytes(size: Int): ByteArray {
            val bytes = ByteArray(size)
            SecureRandom().nextBytes(bytes)
            return bytes
        }
        
        /**
         * SHA-256 hash function.
         */
        fun sha256(data: ByteArray): ByteArray {
            return MessageDigest.getInstance("SHA-256").digest(data)
        }
        
        /**
         * HMAC-SHA256 keyed hash.
         */
        fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(key, "HmacSHA256"))
            return mac.doFinal(data)
        }
        
        /**
         * HKDF-SHA256 key derivation (RFC 5869).
         */
        fun hkdf(ikm: ByteArray, info: ByteArray, length: Int = KEY_SIZE): ByteArray {
            // Extract: PRK = HMAC-SHA256(salt, IKM)
            val salt = ByteArray(KEY_SIZE) // Zero salt
            val prk = hmacSha256(salt, ikm)
            
            // Expand: OKM = HMAC-SHA256(PRK, T || info || counter)
            var t = ByteArray(0)
            var okm = ByteArray(0)
            var counter: Byte = 1
            
            while (okm.size < length) {
                t = hmacSha256(prk, t + info + byteArrayOf(counter))
                okm += t
                counter++
            }
            
            return okm.copyOf(length)
        }
        
        /**
         * Constant-time byte array comparison to prevent timing attacks.
         */
        fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
            if (a.size != b.size) return false
            var result = 0
            for (i in a.indices) {
                result = result or (a[i].toInt() xor b[i].toInt())
            }
            return result == 0
        }
        
        // ==================== Static ChaCha20 ====================
        
        private fun rotl(x: Int, n: Int): Int = (x shl n) or (x ushr (32 - n))
        
        private fun quarterRound(state: IntArray, a: Int, b: Int, c: Int, d: Int) {
            state[a] = (state[a] + state[b])
            state[d] = rotl(state[d] xor state[a], 16)
            state[c] = (state[c] + state[d])
            state[b] = rotl(state[b] xor state[c], 12)
            state[a] = (state[a] + state[b])
            state[d] = rotl(state[d] xor state[a], 8)
            state[c] = (state[c] + state[d])
            state[b] = rotl(state[b] xor state[c], 7)
        }
        
        private fun chacha20BlockStatic(key: ByteArray, nonce: ByteArray, counter: Int): ByteArray {
            val state = IntArray(16)
            for (i in 0..3) state[i] = CHACHA_CONSTANTS[i]
            for (i in 0..7) {
                state[4 + i] = ByteBuffer.wrap(key, i * 4, 4).order(ByteOrder.LITTLE_ENDIAN).int
            }
            state[12] = counter
            for (i in 0..2) {
                state[13 + i] = ByteBuffer.wrap(nonce, i * 4, 4).order(ByteOrder.LITTLE_ENDIAN).int
            }
            
            val workingState = state.copyOf()
            repeat(10) {
                quarterRound(workingState, 0, 4, 8, 12)
                quarterRound(workingState, 1, 5, 9, 13)
                quarterRound(workingState, 2, 6, 10, 14)
                quarterRound(workingState, 3, 7, 11, 15)
                quarterRound(workingState, 0, 5, 10, 15)
                quarterRound(workingState, 1, 6, 11, 12)
                quarterRound(workingState, 2, 7, 8, 13)
                quarterRound(workingState, 3, 4, 9, 14)
            }
            
            for (i in 0..15) workingState[i] = (workingState[i] + state[i])
            return ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN).apply {
                workingState.forEach { putInt(it) }
            }.array()
        }
        
        private fun chacha20Static(key: ByteArray, nonce: ByteArray, data: ByteArray, counter: Int = 0): ByteArray {
            val output = ByteArray(data.size)
            var cnt = counter
            var i = 0
            while (i < data.size) {
                val keyStream = chacha20BlockStatic(key, nonce, cnt)
                val blockLen = minOf(64, data.size - i)
                for (j in 0 until blockLen) {
                    output[i + j] = data[i + j] xor keyStream[j]
                }
                cnt++
                i += 64
            }
            return output
        }
        
        private fun hchacha20Static(key: ByteArray, nonce: ByteArray): ByteArray {
            val state = IntArray(16)
            for (i in 0..3) state[i] = CHACHA_CONSTANTS[i]
            for (i in 0..7) {
                state[4 + i] = ByteBuffer.wrap(key, i * 4, 4).order(ByteOrder.LITTLE_ENDIAN).int
            }
            for (i in 0..3) {
                state[12 + i] = ByteBuffer.wrap(nonce, i * 4, 4).order(ByteOrder.LITTLE_ENDIAN).int
            }
            
            repeat(10) {
                quarterRound(state, 0, 4, 8, 12)
                quarterRound(state, 1, 5, 9, 13)
                quarterRound(state, 2, 6, 10, 14)
                quarterRound(state, 3, 7, 11, 15)
                quarterRound(state, 0, 5, 10, 15)
                quarterRound(state, 1, 6, 11, 12)
                quarterRound(state, 2, 7, 8, 13)
                quarterRound(state, 3, 4, 9, 14)
            }
            
            val subkey = ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN)
            for (i in 0..3) subkey.putInt(state[i])
            for (i in 12..15) subkey.putInt(state[i])
            return subkey.array()
        }
        
        /**
         * XChaCha20 encryption/decryption (static version with explicit key).
         */
        fun xchacha20(key: ByteArray, nonce: ByteArray, data: ByteArray): ByteArray {
            require(key.size == 32) { "Key must be 32 bytes" }
            require(nonce.size >= 24) { "Nonce must be at least 24 bytes" }
            
            val subkey = hchacha20Static(key, nonce.copyOf(16))
            val chachaNonce = ByteArray(12)
            System.arraycopy(nonce, 16, chachaNonce, 4, 8)
            return chacha20Static(subkey, chachaNonce, data)
        }
        
        // ==================== Poly1305 ====================
        
        /**
         * Poly1305 MAC (RFC 7539).
         */
        fun poly1305(key: ByteArray, data: ByteArray): ByteArray {
            require(key.size == 32) { "Key must be 32 bytes" }
            
            // Parse key
            val r = clampR(key.copyOf(16))
            val s = key.copyOfRange(16, 32)
            
            // Process blocks
            var acc = longArrayOf(0, 0, 0, 0, 0)  // 130-bit accumulator
            
            for (i in data.indices step 16) {
                val blockEnd = minOf(i + 16, data.size)
                val block = data.copyOfRange(i, blockEnd)
                
                // Add high bit
                val n = ByteArray(17)
                System.arraycopy(block, 0, n, 0, block.size)
                n[block.size] = 1
                
                // Accumulate
                val num = bytesToNum(n)
                for (j in 0..4) acc[j] += num[j]
                
                // Multiply by r and reduce mod 2^130-5
                acc = mulR(acc, r)
            }
            
            // Final reduction and add s
            val result = finalizeTag(acc, s)
            return result
        }
        
        private fun clampR(r: ByteArray): LongArray {
            val rLongs = LongArray(5)
            val buf = ByteBuffer.wrap(r).order(ByteOrder.LITTLE_ENDIAN)
            
            val r0 = buf.int.toLong() and 0xFFFFFFFFL
            val r1 = buf.int.toLong() and 0xFFFFFFFFL
            val r2 = buf.int.toLong() and 0xFFFFFFFFL
            val r3 = buf.int.toLong() and 0xFFFFFFFFL
            
            // Apply clamping
            rLongs[0] = (r0 and 0x0FFFFFFFL)
            rLongs[1] = ((r0 shr 26) or (r1 shl 6)) and 0x3FFFF03L
            rLongs[2] = ((r1 shr 20) or (r2 shl 12)) and 0x3FFC0FFL
            rLongs[3] = ((r2 shr 14) or (r3 shl 18)) and 0x3F03FFFL
            rLongs[4] = (r3 shr 8) and 0x00FFFFFL
            
            return rLongs
        }
        
        private fun bytesToNum(bytes: ByteArray): LongArray {
            val buf = ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN)
            buf.put(bytes)
            buf.rewind()
            
            val h = LongArray(5)
            val t0 = buf.int.toLong() and 0xFFFFFFFFL
            val t1 = buf.int.toLong() and 0xFFFFFFFFL
            val t2 = buf.int.toLong() and 0xFFFFFFFFL
            val t3 = buf.int.toLong() and 0xFFFFFFFFL
            val t4 = if (bytes.size > 16) (buf.get().toLong() and 0xFFL) else 0L
            
            h[0] = t0 and 0x3FFFFFFL
            h[1] = ((t0 shr 26) or (t1 shl 6)) and 0x3FFFFFFL
            h[2] = ((t1 shr 20) or (t2 shl 12)) and 0x3FFFFFFL
            h[3] = ((t2 shr 14) or (t3 shl 18)) and 0x3FFFFFFL
            h[4] = (t3 shr 8) or (t4 shl 24)
            
            return h
        }
        
        private fun mulR(h: LongArray, r: LongArray): LongArray {
            // Poly1305 multiplication mod 2^130-5
            val result = LongArray(5)
            
            for (i in 0..4) {
                for (j in 0..4) {
                    val mult = h[i] * r[j]
                    result[(i + j) % 5] += if (i + j >= 5) mult * 5 else mult
                }
            }
            
            // Carry propagation
            for (i in 0..4) {
                result[(i + 1) % 5] += result[i] shr 26
                result[i] = result[i] and 0x3FFFFFFL
            }
            
            return result
        }
        
        private fun finalizeTag(h: LongArray, s: ByteArray): ByteArray {
            // Final carry propagation
            val acc = h.copyOf()
            acc[1] += acc[0] shr 26; acc[0] = acc[0] and 0x3FFFFFFL
            acc[2] += acc[1] shr 26; acc[1] = acc[1] and 0x3FFFFFFL
            acc[3] += acc[2] shr 26; acc[2] = acc[2] and 0x3FFFFFFL
            acc[4] += acc[3] shr 26; acc[3] = acc[3] and 0x3FFFFFFL
            acc[0] += (acc[4] shr 26) * 5; acc[4] = acc[4] and 0x3FFFFFFL
            acc[1] += acc[0] shr 26; acc[0] = acc[0] and 0x3FFFFFFL
            
            // Convert to bytes
            var h0 = acc[0] or (acc[1] shl 26)
            var h1 = (acc[1] shr 6) or (acc[2] shl 20)
            var h2 = (acc[2] shr 12) or (acc[3] shl 14)
            var h3 = (acc[3] shr 18) or (acc[4] shl 8)
            
            // Add s
            val sBuf = ByteBuffer.wrap(s).order(ByteOrder.LITTLE_ENDIAN)
            val s0 = sBuf.int.toLong() and 0xFFFFFFFFL
            val s1 = sBuf.int.toLong() and 0xFFFFFFFFL
            val s2 = sBuf.int.toLong() and 0xFFFFFFFFL
            val s3 = sBuf.int.toLong() and 0xFFFFFFFFL
            
            h0 = h0 and 0xFFFFFFFFL
            h0 += s0
            h1 = (h1 and 0xFFFFFFFFL) + s1 + (h0 shr 32)
            h2 = (h2 and 0xFFFFFFFFL) + s2 + (h1 shr 32)
            h3 = (h3 and 0xFFFFFFFFL) + s3 + (h2 shr 32)
            
            return ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
                .putInt(h0.toInt())
                .putInt(h1.toInt())
                .putInt(h2.toInt())
                .putInt(h3.toInt())
                .array()
        }
        
        // ==================== XChaCha20-Poly1305 AEAD ====================
        
        private fun pad16(len: Int): ByteArray = ByteArray((16 - (len % 16)) % 16)
        
        /**
         * XChaCha20-Poly1305 authenticated encryption.
         */
        fun aeadEncrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, ad: ByteArray?): ByteArray {
            require(key.size == 32) { "Key must be 32 bytes" }
            require(nonce.size >= 24) { "Nonce must be at least 24 bytes" }
            
            val aad = ad ?: ByteArray(0)
            
            // Derive subkey
            val subkey = hchacha20Static(key, nonce.copyOf(16))
            val chachaNonce = ByteArray(12)
            System.arraycopy(nonce, 16, chachaNonce, 4, 8)
            
            // Generate Poly1305 key from first block
            val polyKey = chacha20BlockStatic(subkey, chachaNonce, 0).copyOf(32)
            
            // Encrypt with counter starting at 1
            val ciphertext = chacha20Static(subkey, chachaNonce, plaintext, 1)
            
            // Build Poly1305 input: AD || pad || CT || pad || len(AD) || len(CT)
            val polyInput = ByteBuffer.allocate(
                aad.size + pad16(aad.size).size +
                ciphertext.size + pad16(ciphertext.size).size + 16
            ).order(ByteOrder.LITTLE_ENDIAN)
                .put(aad).put(pad16(aad.size))
                .put(ciphertext).put(pad16(ciphertext.size))
                .putLong(aad.size.toLong())
                .putLong(ciphertext.size.toLong())
                .array()
            
            val tag = poly1305(polyKey, polyInput)
            
            return ciphertext + tag
        }
        
        /**
         * XChaCha20-Poly1305 authenticated decryption.
         * Returns null if authentication fails.
         */
        fun aeadDecrypt(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, ad: ByteArray?): ByteArray? {
            require(key.size == 32) { "Key must be 32 bytes" }
            require(nonce.size >= 24) { "Nonce must be at least 24 bytes" }
            if (ciphertext.size < 16) return null
            
            val aad = ad ?: ByteArray(0)
            
            // Split ciphertext and tag
            val ct = ciphertext.copyOf(ciphertext.size - 16)
            val receivedTag = ciphertext.copyOfRange(ciphertext.size - 16, ciphertext.size)
            
            // Derive subkey
            val subkey = hchacha20Static(key, nonce.copyOf(16))
            val chachaNonce = ByteArray(12)
            System.arraycopy(nonce, 16, chachaNonce, 4, 8)
            
            // Generate Poly1305 key
            val polyKey = chacha20BlockStatic(subkey, chachaNonce, 0).copyOf(32)
            
            // Verify tag
            val polyInput = ByteBuffer.allocate(
                aad.size + pad16(aad.size).size +
                ct.size + pad16(ct.size).size + 16
            ).order(ByteOrder.LITTLE_ENDIAN)
                .put(aad).put(pad16(aad.size))
                .put(ct).put(pad16(ct.size))
                .putLong(aad.size.toLong())
                .putLong(ct.size.toLong())
                .array()
            
            val expectedTag = poly1305(polyKey, polyInput)
            
            if (!constantTimeEquals(expectedTag, receivedTag)) {
                return null  // Authentication failed
            }
            
            // Decrypt
            return chacha20Static(subkey, chachaNonce, ct, 1)
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
    
    // Instance keys (internal for wrapper access)
    internal val chachaKey: ByteArray
    private val hmacKey: ByteArray
    
    init {
        require(token.length >= 32) { "Token must be ≥32 characters" }
        
        val tokenBytes = token.toByteArray(Charsets.UTF_8)
        val masterKey = sha256(tokenBytes)
        
        // CRYPTO-03 FIX: Key separation using HKDF
        chachaKey = hkdf(masterKey, "wakelink_encryption_v2".toByteArray())
        hmacKey = hkdf(masterKey, "wakelink_authentication_v2".toByteArray())
    }
    
    // ==================== ChaCha20 Core ====================
    
    private fun chacha20QuarterRound(state: IntArray, a: Int, b: Int, c: Int, d: Int) {
        state[a] = (state[a] + state[b])
        state[d] = rotl(state[d] xor state[a], 16)
        state[c] = (state[c] + state[d])
        state[b] = rotl(state[b] xor state[c], 12)
        state[a] = (state[a] + state[b])
        state[d] = rotl(state[d] xor state[a], 8)
        state[c] = (state[c] + state[d])
        state[b] = rotl(state[b] xor state[c], 7)
    }
    
    private fun rotl(x: Int, n: Int): Int = (x shl n) or (x ushr (32 - n))
    
    private fun chacha20Block(key: ByteArray, nonce: ByteArray, counter: Int): ByteArray {
        val state = IntArray(16)
        
        // Constants (0-3)
        for (i in 0..3) state[i] = CHACHA_CONSTANTS[i]
        
        // Key (4-11) - little-endian
        for (i in 0..7) {
            state[4 + i] = ByteBuffer.wrap(key, i * 4, 4).order(ByteOrder.LITTLE_ENDIAN).int
        }
        
        // Counter (12)
        state[12] = counter
        
        // Nonce (13-15) - little-endian, expects 12 bytes
        for (i in 0..2) {
            state[13 + i] = ByteBuffer.wrap(nonce, i * 4, 4).order(ByteOrder.LITTLE_ENDIAN).int
        }
        
        val workingState = state.copyOf()
        
        // 20 rounds (10 double rounds)
        repeat(10) {
            // Column rounds
            chacha20QuarterRound(workingState, 0, 4, 8, 12)
            chacha20QuarterRound(workingState, 1, 5, 9, 13)
            chacha20QuarterRound(workingState, 2, 6, 10, 14)
            chacha20QuarterRound(workingState, 3, 7, 11, 15)
            // Diagonal rounds
            chacha20QuarterRound(workingState, 0, 5, 10, 15)
            chacha20QuarterRound(workingState, 1, 6, 11, 12)
            chacha20QuarterRound(workingState, 2, 7, 8, 13)
            chacha20QuarterRound(workingState, 3, 4, 9, 14)
        }
        
        // Add original state
        for (i in 0..15) workingState[i] = (workingState[i] + state[i])
        
        // Convert to bytes (little-endian)
        return ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN).apply {
            workingState.forEach { putInt(it) }
        }.array()
    }
    
    private fun chacha20Encrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray): ByteArray {
        val ciphertext = ByteArray(plaintext.size)
        var counter = 0
        
        var i = 0
        while (i < plaintext.size) {
            val keyStream = chacha20Block(key, nonce, counter)
            val blockLen = minOf(64, plaintext.size - i)
            
            for (j in 0 until blockLen) {
                ciphertext[i + j] = plaintext[i + j] xor keyStream[j]
            }
            
            counter++
            i += 64
        }
        
        return ciphertext
    }
    
    // ==================== XChaCha20 (Extended Nonce) ====================
    
    /**
     * HChaCha20 key derivation function.
     * Takes 256-bit key and 128-bit nonce, produces 256-bit subkey.
     */
    private fun hchacha20(key: ByteArray, nonce: ByteArray): ByteArray {
        val state = IntArray(16)
        
        // Constants (0-3)
        for (i in 0..3) state[i] = CHACHA_CONSTANTS[i]
        
        // Key (4-11)
        for (i in 0..7) {
            state[4 + i] = ByteBuffer.wrap(key, i * 4, 4).order(ByteOrder.LITTLE_ENDIAN).int
        }
        
        // Nonce (12-15) - 16 bytes for HChaCha20
        for (i in 0..3) {
            state[12 + i] = ByteBuffer.wrap(nonce, i * 4, 4).order(ByteOrder.LITTLE_ENDIAN).int
        }
        
        // 20 rounds (10 double rounds) - NO final addition
        repeat(10) {
            chacha20QuarterRound(state, 0, 4, 8, 12)
            chacha20QuarterRound(state, 1, 5, 9, 13)
            chacha20QuarterRound(state, 2, 6, 10, 14)
            chacha20QuarterRound(state, 3, 7, 11, 15)
            chacha20QuarterRound(state, 0, 5, 10, 15)
            chacha20QuarterRound(state, 1, 6, 11, 12)
            chacha20QuarterRound(state, 2, 7, 8, 13)
            chacha20QuarterRound(state, 3, 4, 9, 14)
        }
        
        // Extract subkey: words 0-3 and 12-15
        val subkey = ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN)
        for (i in 0..3) subkey.putInt(state[i])
        for (i in 12..15) subkey.putInt(state[i])
        
        return subkey.array()
    }
    
    /**
     * XChaCha20 encryption with 24-byte nonce.
     * Uses HChaCha20 for key derivation then ChaCha20 with modified nonce.
     */
    fun xchacha20(nonce: ByteArray, plaintext: ByteArray): ByteArray {
        require(nonce.size == NONCE_SIZE) { "XChaCha20 requires 24-byte nonce" }
        
        // 1. Derive subkey using HChaCha20 with first 16 bytes of nonce
        val subkey = hchacha20(chachaKey, nonce.copyOf(16))
        
        // 2. Create ChaCha20 nonce: 0x00000000 || nonce[16:24]
        val chachaNonce = ByteArray(12)
        System.arraycopy(nonce, 16, chachaNonce, 4, 8)
        
        // 3. Use ChaCha20 with subkey and modified nonce
        return chacha20Encrypt(subkey, chachaNonce, plaintext)
    }
    
    // ==================== Public API ====================
    
    /**
     * Calculate HMAC-SHA256 signature for data string.
     */
    fun calculateHmac(data: String): String {
        return hmacSha256(hmacKey, data.toByteArray(Charsets.UTF_8)).toHex()
    }
    
    /**
     * Verify HMAC signature using constant-time comparison.
     * Prevents timing attacks that could leak signature information.
     */
    fun verifyHmac(data: String, signature: String): Boolean {
        val expected = hmacSha256(hmacKey, data.toByteArray(Charsets.UTF_8))
        val received = try {
            signature.lowercase().hexToByteArray()
        } catch (e: Exception) {
            return false
        }
        return constantTimeEquals(expected, received)
    }
    
    /**
     * Encrypt plaintext and return hex-encoded payload.
     * Format: [2B length BE] + [ciphertext] + [24B nonce]
     */
    fun createSecurePayload(plaintext: String): String {
        val data = plaintext.toByteArray(Charsets.UTF_8).let {
            if (it.size > 500) it.copyOf(500) else it
        }
        val nonce = randomBytes(NONCE_SIZE)
        
        // XChaCha20 encrypt
        val cipher = xchacha20(nonce, data)
        
        // Format: [2B length BE] + [ciphertext] + [24B nonce]
        val packet = ByteBuffer.allocate(2 + cipher.size + NONCE_SIZE)
            .order(ByteOrder.BIG_ENDIAN)
            .putShort(data.size.toShort())
            .put(cipher)
            .put(nonce)
            .array()
        
        return packet.toHex()
    }
    
    /**
     * Decrypt hex-encoded payload.
     */
    fun decryptPayload(hexPayload: String): Result<String> {
        return try {
            val packet = hexPayload.hexToByteArray()
            
            // Minimum: 2 (length) + 0 (data) + 24 (nonce) = 26 bytes
            if (packet.size < 26) {
                return Result.failure(Exception("Packet too short"))
            }
            
            val length = ByteBuffer.wrap(packet, 0, 2).order(ByteOrder.BIG_ENDIAN).short.toInt() and 0xFFFF
            
            if (length > 500 || packet.size < 2 + length + NONCE_SIZE) {
                return Result.failure(Exception("Invalid packet size"))
            }
            
            val cipher = packet.copyOfRange(2, 2 + length)
            val nonce = packet.copyOfRange(packet.size - NONCE_SIZE, packet.size)
            
            // XChaCha20 decrypt (same as encrypt, symmetric cipher)
            val plainBytes = xchacha20(nonce, cipher)
            Result.success(String(plainBytes, Charsets.UTF_8))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
