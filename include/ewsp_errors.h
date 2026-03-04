/**
 * @file ewsp_errors.h
 * @brief EWSP Core Library - Unified Error Codes
 * 
 * Consistent error codes across all platforms and transports.
 * Keeps in sync with:
 * - Firmware: packet.cpp error strings
 * - Server: websocket.py error responses  
 * - Android: WakeLinkError.kt
 * - Python: errors.py
 * 
 * @author deadboizxc
 * @version 1.0
 */

#ifndef EWSP_ERRORS_H
#define EWSP_ERRORS_H

#include "ewsp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Error Code Enumeration
 * ============================================================================ */

/**
 * @brief EWSP unified error codes.
 * 
 * Negative values indicate errors.
 * Zero indicates success.
 * Positive values reserved for warnings.
 */
typedef enum {
    /* Success */
    EWSP_OK = 0,                       /**< Operation successful */
    
    /* Connection errors (1xx) */
    EWSP_ERR_TIMEOUT = -100,           /**< Operation timed out */
    EWSP_ERR_CONNECTION_REFUSED = -101,/**< Connection refused */
    EWSP_ERR_CONNECTION_ERROR = -102,  /**< Generic connection error */
    EWSP_ERR_NO_RESPONSE = -103,       /**< No response received */
    EWSP_ERR_DISCONNECTED = -104,      /**< Connection lost */
    
    /* Authentication errors (2xx) */
    EWSP_ERR_AUTH_FAILED = -200,       /**< Authentication failed */
    EWSP_ERR_INVALID_TOKEN = -201,     /**< Invalid device token */
    EWSP_ERR_SESSION_EXPIRED = -202,   /**< Session has expired */
    EWSP_ERR_TOKEN_TOO_SHORT = -203,   /**< Token less than 32 chars */
    
    /* Protocol errors (3xx) */
    EWSP_ERR_INVALID_SIGNATURE = -300, /**< HMAC signature mismatch */
    EWSP_ERR_REPLAY_DETECTED = -301,   /**< Replay attack detected */
    EWSP_ERR_BAD_SEQUENCE = -302,      /**< Sequence number invalid */
    EWSP_ERR_SEQ_JUMP_TOO_LARGE = -303,/**< Sequence jumped too far */
    EWSP_ERR_BAD_PACKET = -304,        /**< Malformed packet */
    EWSP_ERR_PAYLOAD_TOO_LARGE = -305, /**< Payload exceeds limit */
    EWSP_ERR_BAD_VERSION = -306,       /**< Protocol version mismatch */
    EWSP_ERR_MISSING_FIELD = -307,     /**< Required field missing */
    
    /* Chain errors (4xx) - Protocol v1.0 Blockchain */
    EWSP_ERR_CHAIN_BROKEN = -400,      /**< prev_hash doesn't match */
    EWSP_ERR_INVALID_GENESIS = -401,   /**< Bad genesis hash */
    EWSP_ERR_CHAIN_DESYNC = -402,      /**< Chains out of sync */
    EWSP_ERR_CHAIN_RESET_REQUIRED = -403, /**< Need to reset chain */
    
    /* Crypto errors (5xx) */
    EWSP_ERR_CRYPTO_DISABLED = -500,   /**< Encryption disabled */
    EWSP_ERR_DECRYPT_FAILED = -501,    /**< Decryption failed */
    EWSP_ERR_ENCRYPT_FAILED = -502,    /**< Encryption failed */
    EWSP_ERR_INVALID_KEY = -503,       /**< Bad key format */
    EWSP_ERR_INVALID_NONCE = -504,     /**< Bad nonce format */
    EWSP_ERR_HMAC_FAILED = -505,       /**< HMAC calculation failed */
    EWSP_ERR_CRYPTO_UNAVAILABLE = -506,/**< No secure RNG available */
    EWSP_ERR_INVALID_LENGTH = -507,    /**< Invalid data length */
    
    /* JSON errors (6xx) */
    EWSP_ERR_JSON_PARSE = -600,        /**< JSON parsing failed */
    EWSP_ERR_JSON_SERIALIZE = -601,    /**< JSON serialization failed */
    EWSP_ERR_INVALID_JSON = -602,      /**< Invalid JSON structure */
    EWSP_ERR_JSON_TOO_DEEP = -603,     /**< JSON nesting too deep */
    
    /* Command errors (7xx) */
    EWSP_ERR_UNKNOWN_COMMAND = -700,   /**< Command not recognized */
    EWSP_ERR_INVALID_PARAMS = -701,    /**< Invalid command parameters */
    EWSP_ERR_COMMAND_FAILED = -702,    /**< Command execution failed */
    EWSP_ERR_NOT_SUPPORTED = -703,     /**< Command not supported */
    
    /* Rate limiting (8xx) */
    EWSP_ERR_RATE_LIMITED = -800,      /**< Too many requests */
    EWSP_ERR_LIMIT_EXCEEDED = -801,    /**< Limit exceeded */
    EWSP_ERR_LOCKED_OUT = -802,        /**< Temporarily locked out */
    
    /* Device errors (9xx) */
    EWSP_ERR_DEVICE_NOT_FOUND = -900,  /**< Device not registered */
    EWSP_ERR_DEVICE_OFFLINE = -901,    /**< Device is offline */
    EWSP_ERR_DEVICE_BUSY = -902,       /**< Device is busy */
    
    /* Memory/Resource errors (10xx) */
    EWSP_ERR_OUT_OF_MEMORY = -1000,    /**< Memory allocation failed */
    EWSP_ERR_BUFFER_TOO_SMALL = -1001, /**< Output buffer too small */
    EWSP_ERR_RESOURCE_BUSY = -1002,    /**< Resource in use */
    
    /* Generic errors */
    EWSP_ERR_INTERNAL = -9998,         /**< Internal library error */
    EWSP_ERR_UNKNOWN = -9999           /**< Unknown error */
    
} ewsp_error_t;

/* ============================================================================
 * Error Categories
 * ============================================================================ */

/**
 * @brief Check if error is retryable.
 * 
 * Retryable errors can be resolved by retry with backoff:
 * - Timeout
 * - Connection errors
 * - Rate limiting
 * - Device offline
 */
static inline bool ewsp_error_is_retryable(ewsp_error_t err) {
    switch (err) {
        case EWSP_ERR_TIMEOUT:
        case EWSP_ERR_CONNECTION_ERROR:
        case EWSP_ERR_NO_RESPONSE:
        case EWSP_ERR_DISCONNECTED:
        case EWSP_ERR_DEVICE_OFFLINE:
        case EWSP_ERR_RATE_LIMITED:
        case EWSP_ERR_DEVICE_BUSY:
            return true;
        default:
            return false;
    }
}

/**
 * @brief Check if error is fatal (requires user action).
 * 
 * Fatal errors cannot be resolved by retry:
 * - Auth failures
 * - Crypto errors
 * - Invalid token
 */
static inline bool ewsp_error_is_fatal(ewsp_error_t err) {
    switch (err) {
        case EWSP_ERR_AUTH_FAILED:
        case EWSP_ERR_INVALID_TOKEN:
        case EWSP_ERR_INVALID_SIGNATURE:
        case EWSP_ERR_CRYPTO_DISABLED:
        case EWSP_ERR_DEVICE_NOT_FOUND:
        case EWSP_ERR_TOKEN_TOO_SHORT:
            return true;
        default:
            return false;
    }
}

/**
 * @brief Check if error requires chain reset.
 * 
 * Chain errors that require reset to genesis:
 * - Chain broken
 * - Desync
 */
static inline bool ewsp_error_needs_chain_reset(ewsp_error_t err) {
    switch (err) {
        case EWSP_ERR_CHAIN_BROKEN:
        case EWSP_ERR_CHAIN_DESYNC:
        case EWSP_ERR_CHAIN_RESET_REQUIRED:
        case EWSP_ERR_REPLAY_DETECTED:
            return true;
        default:
            return false;
    }
}

/* ============================================================================
 * Error String Mapping
 * ============================================================================ */

/**
 * @brief Get error code as string constant.
 * 
 * Returns the error code name (e.g., "INVALID_SIGNATURE").
 * Used for JSON responses and logging.
 * 
 * @param err Error code.
 * @return Error code string (never NULL).
 */
const char* ewsp_error_code_str(ewsp_error_t err);

/**
 * @brief Get human-readable error description.
 * 
 * @param err Error code.
 * @return Error description (never NULL).
 */
const char* ewsp_error_message(ewsp_error_t err);

/**
 * @brief Parse error code from string.
 * 
 * Maps error string from firmware/server response to error code.
 * 
 * @param str Error string (e.g., "INVALID_SIGNATURE").
 * @return Error code, or EWSP_ERR_UNKNOWN if not recognized.
 */
ewsp_error_t ewsp_error_from_str(const char* str);

/* ============================================================================
 * Error Info Structure
 * ============================================================================ */

/**
 * @brief Extended error information.
 * 
 * Contains full error context for debugging and reporting.
 */
typedef struct {
    ewsp_error_t code;         /**< Error code */
    const char* code_str;      /**< Error code as string */
    const char* message;       /**< Human-readable message */
    bool is_retryable;         /**< Can retry with backoff */
    bool is_fatal;             /**< Requires user action */
    bool needs_chain_reset;    /**< Requires chain reset */
    int retry_after_seconds;   /**< Suggested retry delay (0 = default) */
    char detail[256];          /**< Additional detail (optional) */
} ewsp_error_info_t;

/**
 * @brief Get full error information.
 * 
 * @param err Error code.
 * @param info Output error info structure.
 */
void ewsp_error_get_info(ewsp_error_t err, ewsp_error_info_t* info);

/**
 * @brief Set error detail message.
 * 
 * @param info Error info to update.
 * @param detail Detail message (will be truncated if too long).
 */
void ewsp_error_set_detail(ewsp_error_info_t* info, const char* detail);

#ifdef __cplusplus
}
#endif

#endif /* EWSP_ERRORS_H */
