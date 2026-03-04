/**
 * @file ewsp_types.h
 * @brief EWSP Core Library - Base Types
 * 
 * Platform-independent type definitions for all EWSP modules.
 * Ensures consistent types across embedded (ESP8266/ESP32) and
 * high-level language bindings (Python, Kotlin, Swift).
 * 
 * @author deadboizxc
 * @version 1.0
 */

#ifndef EWSP_TYPES_H
#define EWSP_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Size Constants
 * ============================================================================ */

/** SHA256 digest size in bytes */
#define EWSP_SHA256_SIZE        32

/** HMAC-SHA256 output size in bytes */
#define EWSP_HMAC_SIZE          32

/** XChaCha20 key size in bytes */
#define EWSP_KEY_SIZE           32

/** XChaCha20 nonce size in bytes (24 for XChaCha20) */
#define EWSP_NONCE_SIZE         24

/** ChaCha20 nonce size in bytes (12 for standard) */
#define EWSP_CHACHA_NONCE_SIZE  12

/** SHA256 hash as hex string (64 chars + null) */
#define EWSP_HASH_HEX_SIZE      65

/** Minimum token length in characters */
#define EWSP_MIN_TOKEN_LEN      32

/** Maximum device ID length */
#define EWSP_MAX_DEVICE_ID_LEN  32

/** Maximum command name length */
#define EWSP_MAX_COMMAND_LEN    32

/** Request ID length (8 chars) */
#define EWSP_REQUEST_ID_LEN     8

/** Maximum packet payload size (after encryption) */
#define EWSP_MAX_PAYLOAD_SIZE   4096

/** Maximum inner JSON size (before encryption) */
#define EWSP_MAX_INNER_JSON     2048

/** Maximum outer JSON size (final packet) */
#define EWSP_MAX_OUTER_JSON     8192

/** Genesis hash - 64 zeros */
#define EWSP_GENESIS_HASH       "0000000000000000000000000000000000000000000000000000000000000000"

/* ============================================================================
 * Base Types
 * ============================================================================ */

/** Byte type */
typedef uint8_t ewsp_byte_t;

/** Size type */
typedef size_t ewsp_size_t;

/** Sequence number type (64-bit for large counters) */
typedef uint64_t ewsp_seq_t;

/** Timestamp type (milliseconds since epoch) */
typedef uint64_t ewsp_timestamp_t;

/* ============================================================================
 * Fixed-Size Buffer Types
 * ============================================================================ */

/** SHA256 hash buffer (32 bytes) */
typedef struct {
    ewsp_byte_t bytes[EWSP_SHA256_SIZE];
} ewsp_hash_t;

/** Encryption key buffer (32 bytes) */
typedef struct {
    ewsp_byte_t bytes[EWSP_KEY_SIZE];
} ewsp_key_t;

/** XChaCha20 nonce buffer (24 bytes) */
typedef struct {
    ewsp_byte_t bytes[EWSP_NONCE_SIZE];
} ewsp_nonce_t;

/** HMAC signature buffer (32 bytes) */
typedef struct {
    ewsp_byte_t bytes[EWSP_HMAC_SIZE];
} ewsp_signature_t;

/* ============================================================================
 * String Types (Fixed-Size)
 * ============================================================================ */

/** Device ID string */
typedef struct {
    char value[EWSP_MAX_DEVICE_ID_LEN + 1];
} ewsp_device_id_t;

/** Command name string */
typedef struct {
    char value[EWSP_MAX_COMMAND_LEN + 1];
} ewsp_command_name_t;

/** Request ID string */
typedef struct {
    char value[EWSP_REQUEST_ID_LEN + 1];
} ewsp_request_id_t;

/** Hash as hex string (64 chars + null) */
typedef struct {
    char value[EWSP_HASH_HEX_SIZE];
} ewsp_hash_hex_t;

/* ============================================================================
 * Utility Macros
 * ============================================================================ */

/** Calculate array length */
#define EWSP_ARRAY_LEN(arr) (sizeof(arr) / sizeof((arr)[0]))

/** Minimum of two values */
#define EWSP_MIN(a, b) (((a) < (b)) ? (a) : (b))

/** Maximum of two values */
#define EWSP_MAX(a, b) (((a) > (b)) ? (a) : (b))

/** Check if value is in range [min, max] */
#define EWSP_IN_RANGE(val, min, max) (((val) >= (min)) && ((val) <= (max)))

/* ============================================================================
 * Result Type
 * ============================================================================ */

/**
 * @brief Generic result with success flag and optional data.
 * 
 * Used for functions that can fail with specific error info.
 */
typedef struct {
    bool success;
    int error_code;
    const char* error_message;
} ewsp_result_t;

/* ============================================================================
 * Buffer Helpers
 * ============================================================================ */

/**
 * @brief Initialize hash to zero.
 */
static inline void ewsp_hash_zero(ewsp_hash_t* h) {
    memset(h->bytes, 0, EWSP_SHA256_SIZE);
}

/**
 * @brief Compare two hashes for equality (constant-time).
 * @return true if equal, false otherwise.
 * 
 * CRYPTO-04 FIX: Uses constant-time comparison to prevent timing attacks.
 */
static inline bool ewsp_hash_equal(const ewsp_hash_t* a, const ewsp_hash_t* b) {
    volatile uint8_t result = 0;
    for (size_t i = 0; i < EWSP_SHA256_SIZE; i++) {
        result |= a->bytes[i] ^ b->bytes[i];
    }
    return result == 0;
}

/**
 * @brief Copy hash from source to destination.
 */
static inline void ewsp_hash_copy(ewsp_hash_t* dst, const ewsp_hash_t* src) {
    memcpy(dst->bytes, src->bytes, EWSP_SHA256_SIZE);
}

/**
 * @brief Initialize key to zero.
 */
static inline void ewsp_key_zero(ewsp_key_t* k) {
    memset(k->bytes, 0, EWSP_KEY_SIZE);
}

/**
 * @brief Secure zero memory (not optimized away).
 */
static inline void ewsp_secure_memzero(void* ptr, size_t len) {
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    while (len--) {
        *p++ = 0;
    }
}

#ifdef __cplusplus
}
#endif

#endif /* EWSP_TYPES_H */
