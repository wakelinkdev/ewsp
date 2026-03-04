/**
 * @file ewsp_errors.c
 * @brief EWSP Core Library - Error Handling Implementation
 * 
 * @author deadboizxc
 * @version 1.0
 */

#include "ewsp_errors.h"
#include <string.h>

/* ============================================================================
 * Error String Mapping
 * ============================================================================ */

typedef struct {
    ewsp_error_t code;
    const char* code_str;
    const char* message;
} error_entry_t;

static const error_entry_t error_table[] = {
    /* Success */
    {EWSP_OK, "OK", "Operation successful"},
    
    /* Connection errors */
    {EWSP_ERR_TIMEOUT, "TIMEOUT", "Operation timed out"},
    {EWSP_ERR_CONNECTION_REFUSED, "CONNECTION_REFUSED", "Connection refused"},
    {EWSP_ERR_CONNECTION_ERROR, "CONNECTION_ERROR", "Connection error"},
    {EWSP_ERR_NO_RESPONSE, "NO_RESPONSE", "No response received"},
    {EWSP_ERR_DISCONNECTED, "DISCONNECTED", "Connection lost"},
    
    /* Authentication errors */
    {EWSP_ERR_AUTH_FAILED, "AUTH_FAILED", "Authentication failed"},
    {EWSP_ERR_INVALID_TOKEN, "INVALID_TOKEN", "Invalid device token"},
    {EWSP_ERR_SESSION_EXPIRED, "SESSION_EXPIRED", "Session has expired"},
    {EWSP_ERR_TOKEN_TOO_SHORT, "TOKEN_TOO_SHORT", "Token must be at least 32 characters"},
    
    /* Protocol errors */
    {EWSP_ERR_INVALID_SIGNATURE, "INVALID_SIGNATURE", "HMAC signature mismatch"},
    {EWSP_ERR_REPLAY_DETECTED, "REPLAY_DETECTED", "Replay attack detected"},
    {EWSP_ERR_BAD_SEQUENCE, "BAD_SEQUENCE", "Invalid sequence number"},
    {EWSP_ERR_SEQ_JUMP_TOO_LARGE, "SEQ_JUMP_TOO_LARGE", "Sequence jumped too far"},
    {EWSP_ERR_BAD_PACKET, "BAD_PACKET", "Malformed packet"},
    {EWSP_ERR_PAYLOAD_TOO_LARGE, "PAYLOAD_TOO_LARGE", "Payload exceeds maximum size"},
    {EWSP_ERR_BAD_VERSION, "BAD_VERSION", "Protocol version mismatch"},
    {EWSP_ERR_MISSING_FIELD, "MISSING_FIELD", "Required field missing"},
    
    /* Chain errors */
    {EWSP_ERR_CHAIN_BROKEN, "CHAIN_BROKEN", "Blockchain chain broken - prev_hash mismatch"},
    {EWSP_ERR_INVALID_GENESIS, "INVALID_GENESIS", "Invalid genesis hash"},
    {EWSP_ERR_CHAIN_DESYNC, "CHAIN_DESYNC", "Chains out of sync"},
    {EWSP_ERR_CHAIN_RESET_REQUIRED, "CHAIN_RESET_REQUIRED", "Chain reset required"},
    
    /* Crypto errors */
    {EWSP_ERR_CRYPTO_DISABLED, "CRYPTO_DISABLED", "Encryption is disabled"},
    {EWSP_ERR_DECRYPT_FAILED, "DECRYPT_FAILED", "Decryption failed"},
    {EWSP_ERR_ENCRYPT_FAILED, "ENCRYPT_FAILED", "Encryption failed"},
    {EWSP_ERR_INVALID_KEY, "INVALID_KEY", "Invalid encryption key"},
    {EWSP_ERR_INVALID_NONCE, "INVALID_NONCE", "Invalid nonce"},
    {EWSP_ERR_HMAC_FAILED, "HMAC_FAILED", "HMAC calculation failed"},
    
    /* JSON errors */
    {EWSP_ERR_JSON_PARSE, "JSON_PARSE", "JSON parsing failed"},
    {EWSP_ERR_JSON_SERIALIZE, "JSON_SERIALIZE", "JSON serialization failed"},
    {EWSP_ERR_INVALID_JSON, "INVALID_JSON", "Invalid JSON structure"},
    {EWSP_ERR_JSON_TOO_DEEP, "JSON_TOO_DEEP", "JSON nesting too deep"},
    
    /* Command errors */
    {EWSP_ERR_UNKNOWN_COMMAND, "UNKNOWN_COMMAND", "Command not recognized"},
    {EWSP_ERR_INVALID_PARAMS, "INVALID_PARAMS", "Invalid command parameters"},
    {EWSP_ERR_COMMAND_FAILED, "COMMAND_FAILED", "Command execution failed"},
    {EWSP_ERR_NOT_SUPPORTED, "NOT_SUPPORTED", "Command not supported"},
    
    /* Rate limiting */
    {EWSP_ERR_RATE_LIMITED, "RATE_LIMITED", "Too many requests"},
    {EWSP_ERR_LIMIT_EXCEEDED, "LIMIT_EXCEEDED", "Request limit exceeded"},
    {EWSP_ERR_LOCKED_OUT, "LOCKED_OUT", "Temporarily locked out"},
    
    /* Device errors */
    {EWSP_ERR_DEVICE_NOT_FOUND, "DEVICE_NOT_FOUND", "Device not found"},
    {EWSP_ERR_DEVICE_OFFLINE, "DEVICE_OFFLINE", "Device is offline"},
    {EWSP_ERR_DEVICE_BUSY, "DEVICE_BUSY", "Device is busy"},
    
    /* Memory/Resource errors */
    {EWSP_ERR_OUT_OF_MEMORY, "OUT_OF_MEMORY", "Memory allocation failed"},
    {EWSP_ERR_BUFFER_TOO_SMALL, "BUFFER_TOO_SMALL", "Output buffer too small"},
    {EWSP_ERR_RESOURCE_BUSY, "RESOURCE_BUSY", "Resource is in use"},
    
    /* Generic errors */
    {EWSP_ERR_INTERNAL, "INTERNAL", "Internal library error"},
    {EWSP_ERR_UNKNOWN, "UNKNOWN", "Unknown error"},
};

#define ERROR_TABLE_SIZE (sizeof(error_table) / sizeof(error_table[0]))

const char* ewsp_error_code_str(ewsp_error_t err) {
    for (size_t i = 0; i < ERROR_TABLE_SIZE; i++) {
        if (error_table[i].code == err) {
            return error_table[i].code_str;
        }
    }
    return "UNKNOWN";
}

const char* ewsp_error_message(ewsp_error_t err) {
    for (size_t i = 0; i < ERROR_TABLE_SIZE; i++) {
        if (error_table[i].code == err) {
            return error_table[i].message;
        }
    }
    return "Unknown error";
}

ewsp_error_t ewsp_error_from_str(const char* str) {
    if (!str) {
        return EWSP_ERR_UNKNOWN;
    }
    
    for (size_t i = 0; i < ERROR_TABLE_SIZE; i++) {
        if (strcmp(error_table[i].code_str, str) == 0) {
            return error_table[i].code;
        }
    }
    
    return EWSP_ERR_UNKNOWN;
}

void ewsp_error_get_info(ewsp_error_t err, ewsp_error_info_t* info) {
    if (!info) return;
    
    info->code = err;
    info->code_str = ewsp_error_code_str(err);
    info->message = ewsp_error_message(err);
    info->is_retryable = ewsp_error_is_retryable(err);
    info->is_fatal = ewsp_error_is_fatal(err);
    info->needs_chain_reset = ewsp_error_needs_chain_reset(err);
    info->retry_after_seconds = 0;
    info->detail[0] = '\0';
    
    /* Set retry delay for rate limiting */
    if (err == EWSP_ERR_RATE_LIMITED) {
        info->retry_after_seconds = 5;
    } else if (err == EWSP_ERR_LOCKED_OUT) {
        info->retry_after_seconds = 60;
    }
}

void ewsp_error_set_detail(ewsp_error_info_t* info, const char* detail) {
    if (!info || !detail) return;
    
    size_t len = strlen(detail);
    if (len >= sizeof(info->detail)) {
        len = sizeof(info->detail) - 1;
    }
    
    memcpy(info->detail, detail, len);
    info->detail[len] = '\0';
}
