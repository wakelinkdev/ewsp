/**
 * @file ewsp_crypto.h
 * @brief EWSP Core Library - Cryptographic Primitives
 * 
 * Unified cryptography for WakeLink Protocol v1.0.
 * 
 * Primitives:
 * - SHA-256: Secure hash (FIPS 180-4)
 * - HMAC-SHA256: Message authentication (RFC 2104)
 * - HKDF-SHA256: Key derivation (RFC 5869)
 * - XChaCha20: Extended nonce cipher
 * 
 * @author deadboizxc
 * @version 1.0
 */

#ifndef EWSP_CRYPTO_H
#define EWSP_CRYPTO_H

#include "ewsp_types.h"
#include "ewsp_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * SHA-256
 * ============================================================================ */

/**
 * @brief SHA-256 context structure.
 */
typedef struct {
    uint32_t state[8];          /**< Hash state (H0-H7) */
    uint8_t  buffer[64];        /**< Input buffer */
    uint64_t bitlen;            /**< Total bits processed */
    uint32_t buflen;            /**< Bytes in buffer */
} ewsp_sha256_ctx;

/**
 * @brief Initialize SHA-256 context.
 */
void ewsp_sha256_init(ewsp_sha256_ctx* ctx);

/**
 * @brief Update SHA-256 with data.
 */
void ewsp_sha256_update(ewsp_sha256_ctx* ctx, const uint8_t* data, size_t len);

/**
 * @brief Finalize SHA-256 and output hash.
 */
void ewsp_sha256_final(ewsp_sha256_ctx* ctx, uint8_t hash[32]);

/**
 * @brief One-shot SHA-256 hash.
 */
void ewsp_sha256(const uint8_t* data, size_t len, uint8_t hash[32]);

/**
 * @brief SHA-256 hash to ewsp_hash_t structure.
 */
void ewsp_sha256_to_hash(const uint8_t* data, size_t len, ewsp_hash_t* hash);

/* ============================================================================
 * HMAC-SHA256
 * ============================================================================ */

/**
 * @brief HMAC-SHA256 context structure.
 */
typedef struct {
    ewsp_sha256_ctx inner;      /**< Inner hash context */
    ewsp_sha256_ctx outer;      /**< Outer hash context */
    uint8_t key_pad[64];        /**< Padded key for outer hash */
} ewsp_hmac_ctx;

/**
 * @brief Initialize HMAC-SHA256 context.
 */
void ewsp_hmac_init(ewsp_hmac_ctx* ctx, const uint8_t* key, size_t key_len);

/**
 * @brief Update HMAC with data.
 */
void ewsp_hmac_update(ewsp_hmac_ctx* ctx, const uint8_t* data, size_t len);

/**
 * @brief Finalize HMAC and output MAC.
 */
void ewsp_hmac_final(ewsp_hmac_ctx* ctx, uint8_t mac[32]);

/**
 * @brief One-shot HMAC-SHA256.
 */
void ewsp_hmac_sha256(const uint8_t* key, size_t key_len,
                      const uint8_t* data, size_t data_len,
                      uint8_t mac[32]);

/**
 * @brief Constant-time MAC verification.
 * @return 1 if equal, 0 otherwise.
 */
int ewsp_hmac_verify(const uint8_t mac1[32], const uint8_t mac2[32]);

/* ============================================================================
 * HKDF-SHA256 (RFC 5869)
 * ============================================================================ */

/**
 * @brief HKDF Extract phase.
 */
void ewsp_hkdf_extract(const uint8_t* salt, size_t salt_len,
                       const uint8_t* ikm, size_t ikm_len,
                       uint8_t prk[32]);

/**
 * @brief HKDF Expand phase.
 */
void ewsp_hkdf_expand(const uint8_t prk[32],
                      const uint8_t* info, size_t info_len,
                      uint8_t* okm, size_t okm_len);

/**
 * @brief One-shot HKDF-SHA256.
 */
void ewsp_hkdf(const uint8_t* salt, size_t salt_len,
               const uint8_t* ikm, size_t ikm_len,
               const uint8_t* info, size_t info_len,
               uint8_t* okm, size_t okm_len);

/* ============================================================================
 * ChaCha20 (RFC 7539)
 * ============================================================================ */

/**
 * @brief ChaCha20 encrypt/decrypt.
 */
void ewsp_chacha20(const uint8_t key[32], const uint8_t nonce[12],
                   uint32_t counter,
                   const uint8_t* input, uint8_t* output, size_t len);

/**
 * @brief Generate ChaCha20 keystream block.
 */
void ewsp_chacha20_block(const uint8_t key[32], const uint8_t nonce[12],
                         uint32_t counter, uint8_t block[64]);

/* ============================================================================
 * XChaCha20 (Extended Nonce)
 * ============================================================================ */

/**
 * @brief HChaCha20 key derivation (for XChaCha20).
 */
void ewsp_hchacha20(const uint8_t key[32], const uint8_t nonce[16],
                    uint8_t subkey[32]);

/**
 * @brief XChaCha20 encrypt/decrypt with 24-byte nonce.
 */
void ewsp_xchacha20(const uint8_t key[32], const uint8_t nonce[24],
                    uint32_t counter,
                    const uint8_t* input, uint8_t* output, size_t len);

/* ============================================================================
 * Poly1305 MAC (RFC 7539)
 * ============================================================================ */

/**
 * @brief Poly1305 context structure.
 */
typedef struct {
    uint32_t r[5];              /**< Clamped key r */
    uint32_t h[5];              /**< Accumulator */
    uint32_t pad[4];            /**< One-time pad s */
    uint8_t buffer[16];         /**< Input buffer */
    size_t buflen;              /**< Bytes in buffer */
    bool finalized;             /**< Tag computed */
} ewsp_poly1305_ctx;

/**
 * @brief Initialize Poly1305 context.
 * @param ctx Context to initialize.
 * @param key 32-byte one-time key (r || s).
 */
void ewsp_poly1305_init(ewsp_poly1305_ctx* ctx, const uint8_t key[32]);

/**
 * @brief Update Poly1305 with data.
 */
void ewsp_poly1305_update(ewsp_poly1305_ctx* ctx, const uint8_t* data, size_t len);

/**
 * @brief Finalize Poly1305 and output 16-byte tag.
 */
void ewsp_poly1305_final(ewsp_poly1305_ctx* ctx, uint8_t tag[16]);

/**
 * @brief One-shot Poly1305 MAC.
 */
void ewsp_poly1305(const uint8_t key[32], const uint8_t* data, size_t len, uint8_t tag[16]);

/* ============================================================================
 * XChaCha20-Poly1305 AEAD (RFC 7539 + XChaCha extension)
 * ============================================================================ */

/** AEAD tag size in bytes */
#define EWSP_AEAD_TAG_SIZE 16

/** AEAD nonce size in bytes (XChaCha20 extended nonce) */
#define EWSP_AEAD_NONCE_SIZE 24

/**
 * @brief XChaCha20-Poly1305 authenticated encryption.
 * 
 * Encrypts plaintext and computes authentication tag over:
 * - Associated data (AD)
 * - Ciphertext
 * - Lengths of AD and ciphertext
 * 
 * Output format: [ciphertext || 16-byte tag]
 * 
 * @param key 32-byte encryption key.
 * @param nonce 24-byte unique nonce (MUST be unique per key).
 * @param ad Associated data (authenticated but not encrypted), can be NULL.
 * @param ad_len Length of associated data.
 * @param plaintext Input plaintext.
 * @param plaintext_len Length of plaintext.
 * @param ciphertext Output buffer (size = plaintext_len + 16 for tag).
 * @return EWSP_OK on success.
 */
ewsp_error_t ewsp_aead_encrypt(const uint8_t key[32],
                                const uint8_t nonce[24],
                                const uint8_t* ad, size_t ad_len,
                                const uint8_t* plaintext, size_t plaintext_len,
                                uint8_t* ciphertext);

/**
 * @brief XChaCha20-Poly1305 authenticated decryption.
 * 
 * Verifies authentication tag and decrypts ciphertext.
 * 
 * Input format: [ciphertext || 16-byte tag]
 * 
 * @param key 32-byte encryption key.
 * @param nonce 24-byte nonce used for encryption.
 * @param ad Associated data (same as used for encryption), can be NULL.
 * @param ad_len Length of associated data.
 * @param ciphertext Input ciphertext with appended tag.
 * @param ciphertext_len Length of ciphertext including 16-byte tag.
 * @param plaintext Output buffer (size = ciphertext_len - 16).
 * @return EWSP_OK on success, EWSP_ERR_AUTH_FAILED if tag invalid.
 */
ewsp_error_t ewsp_aead_decrypt(const uint8_t key[32],
                                const uint8_t nonce[24],
                                const uint8_t* ad, size_t ad_len,
                                const uint8_t* ciphertext, size_t ciphertext_len,
                                uint8_t* plaintext);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * @brief Constant-time comparison.
 */
int ewsp_constant_time_compare(const uint8_t* a, const uint8_t* b, size_t len);

/**
 * @brief Secure memory zeroing.
 */
void ewsp_secure_zero(void* ptr, size_t len);

/**
 * @brief Convert bytes to hex string.
 */
void ewsp_bytes_to_hex(const uint8_t* data, size_t len, char* hex);

/**
 * @brief Convert hex string to bytes.
 * @return 0 on success, -1 on error.
 */
int ewsp_hex_to_bytes(const char* hex, uint8_t* data, size_t len);

/**
 * @brief Generate random bytes.
 * 
 * Uses platform-specific secure random source.
 * On ESP32: esp_random()
 * On desktop: /dev/urandom or CryptGenRandom
 * 
 * @param buffer Output buffer.
 * @param len Number of bytes to generate.
 * @return EWSP_OK on success.
 */
ewsp_error_t ewsp_random_bytes(uint8_t* buffer, size_t len);

/* ============================================================================
 * High-Level Crypto API
 * ============================================================================ */

/**
 * @brief Crypto context for packet operations.
 * 
 * Pre-computed keys derived from device token.
 */
typedef struct {
    ewsp_key_t chacha_key;      /**< XChaCha20 encryption key */
    ewsp_key_t hmac_key;        /**< HMAC-SHA256 key */
    bool initialized;           /**< Context is ready */
} ewsp_crypto_ctx;

/**
 * @brief Initialize crypto context from device token.
 * 
 * Derives keys: chacha_key = hmac_key = SHA256(token)
 * 
 * @param ctx Context to initialize.
 * @param token Device token (min 32 chars).
 * @param token_len Token length.
 * @return EWSP_OK on success.
 */
ewsp_error_t ewsp_crypto_init(ewsp_crypto_ctx* ctx, 
                              const char* token, 
                              size_t token_len);

/**
 * @brief Clean up crypto context (secure zero keys).
 */
void ewsp_crypto_cleanup(ewsp_crypto_ctx* ctx);

/**
 * @brief Encrypt plaintext to hex payload.
 * 
 * Format: [2B length BE] + [ciphertext] + [24B nonce] → hex
 * 
 * @param ctx Initialized crypto context.
 * @param plaintext Input plaintext.
 * @param plaintext_len Plaintext length.
 * @param hex_out Output hex string buffer.
 * @param hex_out_size Size of output buffer.
 * @return EWSP_OK on success.
 */
ewsp_error_t ewsp_crypto_encrypt(const ewsp_crypto_ctx* ctx,
                                  const uint8_t* plaintext,
                                  size_t plaintext_len,
                                  char* hex_out,
                                  size_t hex_out_size);

/**
 * @brief Decrypt hex payload to plaintext.
 * 
 * @param ctx Initialized crypto context.
 * @param hex_payload Input hex payload.
 * @param plaintext_out Output plaintext buffer.
 * @param plaintext_size Size of output buffer.
 * @param plaintext_len_out Actual plaintext length.
 * @return EWSP_OK on success.
 */
ewsp_error_t ewsp_crypto_decrypt(const ewsp_crypto_ctx* ctx,
                                  const char* hex_payload,
                                  uint8_t* plaintext_out,
                                  size_t plaintext_size,
                                  size_t* plaintext_len_out);

/**
 * @brief Calculate HMAC signature of data.
 * 
 * @param ctx Initialized crypto context.
 * @param data Input data.
 * @param data_len Data length.
 * @param sig_hex_out Output hex signature (64 chars + null).
 */
void ewsp_crypto_sign(const ewsp_crypto_ctx* ctx,
                      const uint8_t* data,
                      size_t data_len,
                      char sig_hex_out[65]);

/**
 * @brief Verify HMAC signature.
 * 
 * @param ctx Initialized crypto context.
 * @param data Input data.
 * @param data_len Data length.
 * @param sig_hex Expected signature (hex string).
 * @return true if signature matches.
 */
bool ewsp_crypto_verify(const ewsp_crypto_ctx* ctx,
                        const uint8_t* data,
                        size_t data_len,
                        const char* sig_hex);

#ifdef __cplusplus
}
#endif

#endif /* EWSP_CRYPTO_H */
