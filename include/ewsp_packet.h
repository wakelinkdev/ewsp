/**
 * @file ewsp_packet.h
 * @brief EWSP Core Library - Packet Manager
 * 
 * High-level API for creating and processing Protocol v1.0 packets.
 * Handles encryption, signing, chain management, and JSON serialization.
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * PACKET STRUCTURE v1.0
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * Outer JSON:
 * {
 *   "v": "1.0",                    // Protocol version
 *   "id": "WL35080814",            // Device ID  
 *   "seq": 42,                     // Sequence number (monotonic)
 *   "prev": "a1b2c3...",           // SHA256 of previous packet (64 hex)
 *   "p": "encrypted...",           // XChaCha20 encrypted payload
 *   "sig": "hmac..."               // HMAC-SHA256(v|id|seq|prev|p)
 * }
 * 
 * Inner JSON (encrypted):
 * {
 *   "cmd": "wake",                 // Command
 *   "d": {"mac": "AA:BB:..."},     // Command data
 *   "rid": "X7K2M9P1"              // Request ID
 * }
 * 
 * @author deadboizxc
 * @version 1.0
 */

#ifndef EWSP_PACKET_H
#define EWSP_PACKET_H

#include "ewsp_types.h"
#include "ewsp_errors.h"
#include "ewsp_crypto.h"
#include "ewsp_chain.h"
#include "ewsp_models.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Packet Context
 * ============================================================================ */

/**
 * @brief Packet manager context.
 * 
 * Combines crypto context, chain state, and device identity.
 * One context per device connection.
 */
typedef struct {
    ewsp_crypto_ctx crypto;                         /**< Crypto keys */
    ewsp_chain_ctx_t chain;                         /**< Blockchain state */
    char device_id[EWSP_MAX_DEVICE_ID_LEN + 1];    /**< Device identifier */
    bool initialized;                               /**< Context ready */
} ewsp_packet_ctx;

/**
 * @brief Initialize packet context.
 * 
 * @param ctx Context to initialize.
 * @param token Device token (min 32 chars).
 * @param device_id Device identifier.
 * @return EWSP_OK on success.
 */
ewsp_error_t ewsp_packet_init(ewsp_packet_ctx* ctx,
                               const char* token,
                               const char* device_id);

/**
 * @brief Clean up packet context.
 * 
 * Securely zeros keys and resets state.
 */
void ewsp_packet_cleanup(ewsp_packet_ctx* ctx);

/**
 * @brief Reset chains to genesis state.
 * 
 * Call when:
 * - Device re-paired
 * - Protocol error (chain broken)
 * - Session timeout
 */
void ewsp_packet_reset_chains(ewsp_packet_ctx* ctx);

/* ============================================================================
 * Packet Creation
 * ============================================================================ */

/**
 * @brief Create command packet.
 * 
 * Creates a blockchain-linked packet with encrypted command.
 * Automatically increments TX sequence and updates chain.
 * 
 * @param ctx Initialized packet context.
 * @param command Command name (e.g., "wake", "ping").
 * @param data_json Command data as JSON string (can be NULL or "{}").
 * @param packet_out Output buffer for packet JSON.
 * @param packet_out_size Size of output buffer.
 * @return EWSP_OK on success.
 */
ewsp_error_t ewsp_packet_create_command(ewsp_packet_ctx* ctx,
                                         const char* command,
                                         const char* data_json,
                                         char* packet_out,
                                         size_t packet_out_size);

/**
 * @brief Create response packet.
 * 
 * Creates a blockchain-linked response.
 * Response links to the request it answers (uses last_received_hash).
 * 
 * @param ctx Initialized packet context.
 * @param response_json Response data as JSON string.
 * @param packet_out Output buffer for packet JSON.
 * @param packet_out_size Size of output buffer.
 * @return EWSP_OK on success.
 */
ewsp_error_t ewsp_packet_create_response(ewsp_packet_ctx* ctx,
                                          const char* response_json,
                                          char* packet_out,
                                          size_t packet_out_size);

/**
 * @brief Create packet with custom data.
 * 
 * Low-level API for creating packets with arbitrary inner JSON.
 * 
 * @param ctx Packet context.
 * @param inner_json Inner JSON to encrypt.
 * @param use_request_prev Use tx.last_hash (request) vs last_received_hash (response).
 * @param packet_out Output buffer.
 * @param packet_out_size Buffer size.
 * @return EWSP_OK on success.
 */
ewsp_error_t ewsp_packet_create(ewsp_packet_ctx* ctx,
                                 const char* inner_json,
                                 bool use_request_prev,
                                 char* packet_out,
                                 size_t packet_out_size);

/* ============================================================================
 * Packet Processing
 * ============================================================================ */

/**
 * @brief Process incoming packet.
 * 
 * Validates and decrypts an incoming packet:
 * 1. Parse outer JSON
 * 2. Verify protocol version
 * 3. Verify HMAC signature
 * 4. Validate chain (sequence, prev_hash)
 * 5. Decrypt payload
 * 6. Update RX chain
 * 
 * @param ctx Packet context.
 * @param packet_json Incoming packet JSON string.
 * @param result Output result structure.
 * @return EWSP_OK on success, error code otherwise.
 */
ewsp_error_t ewsp_packet_process(ewsp_packet_ctx* ctx,
                                  const char* packet_json,
                                  ewsp_packet_result_t* result);

/**
 * @brief Verify packet signature only (no decrypt).
 * 
 * Useful for relay servers that need to validate packets
 * without accessing encrypted content.
 * 
 * @param crypto Crypto context with keys.
 * @param packet_json Packet JSON string.
 * @return true if signature valid.
 */
bool ewsp_packet_verify_signature(const ewsp_crypto_ctx* crypto,
                                   const char* packet_json);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * @brief Generate random 8-character request ID.
 * 
 * Characters: A-Z, 0-9
 */
void ewsp_packet_generate_rid(char rid_out[9]);

/**
 * @brief Parse outer packet fields (without decryption).
 * 
 * Extracts: version, device_id, sequence, prev_hash, payload, signature
 * 
 * @param packet_json Input JSON.
 * @param outer Output outer packet structure.
 * @return EWSP_OK on success.
 */
ewsp_error_t ewsp_packet_parse_outer(const char* packet_json,
                                      ewsp_outer_packet_t* outer);

/**
 * @brief Build signature data string.
 * 
 * Format: "v|id|seq|prev|p"
 */
ewsp_error_t ewsp_packet_build_sig_data(const ewsp_outer_packet_t* outer,
                                         char* sig_data_out,
                                         size_t sig_data_size);

/* ============================================================================
 * Chain State Accessors
 * ============================================================================ */

/**
 * @brief Get current TX sequence number.
 */
static inline ewsp_seq_t ewsp_packet_tx_seq(const ewsp_packet_ctx* ctx) {
    return ctx->chain.tx.sequence;
}

/**
 * @brief Get current RX sequence number.
 */
static inline ewsp_seq_t ewsp_packet_rx_seq(const ewsp_packet_ctx* ctx) {
    return ctx->chain.rx.sequence;
}

/**
 * @brief Get last TX hash.
 */
static inline const char* ewsp_packet_tx_hash(const ewsp_packet_ctx* ctx) {
    return ctx->chain.tx.last_hash;
}

/**
 * @brief Get last RX hash.
 */
static inline const char* ewsp_packet_rx_hash(const ewsp_packet_ctx* ctx) {
    return ctx->chain.rx.last_hash;
}

/**
 * @brief Check if chains are at genesis state.
 */
static inline bool ewsp_packet_is_genesis(const ewsp_packet_ctx* ctx) {
    return ewsp_chain_is_genesis(&ctx->chain.tx) && 
           ewsp_chain_is_genesis(&ctx->chain.rx);
}

/* ============================================================================
 * State Persistence
 * ============================================================================ */

/**
 * @brief Export packet context state for persistence.
 */
void ewsp_packet_export_state(const ewsp_packet_ctx* ctx, 
                               ewsp_chain_snapshot_t* snapshot);

/**
 * @brief Import packet context state from persistence.
 */
void ewsp_packet_import_state(ewsp_packet_ctx* ctx,
                               const ewsp_chain_snapshot_t* snapshot);

#ifdef __cplusplus
}
#endif

#endif /* EWSP_PACKET_H */
