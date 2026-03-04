/**
 * @file ewsp_chain.h
 * @brief EWSP Core Library - Blockchain Chain Management
 * 
 * Manages blockchain state for Protocol v1.0.
 * Each packet contains SHA256 hash of previous packet.
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * CHAIN STRUCTURE
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 *   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
 *   │  Genesis    │────▶│  Packet 1   │────▶│  Packet 2   │────▶ ...
 *   │ prev: 0x00  │     │ prev: H(G)  │     │ prev: H(P1) │
 *   │ seq: 0      │     │ seq: 1      │     │ seq: 2      │
 *   └─────────────┘     └─────────────┘     └─────────────┘
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * TWO-WAY CHAINS
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * Each direction has independent chain:
 * 
 *   TX Chain (outgoing):   Genesis ──▶ Pkt1 ──▶ Pkt2 ──▶ Pkt3
 *   RX Chain (incoming):   Genesis ──▶ Pkt1 ──▶ Pkt2 ──▶ Pkt3
 * 
 * Response links to request it answers (cross-chain reference).
 * 
 * @author deadboizxc
 * @version 1.0
 */

#ifndef EWSP_CHAIN_H
#define EWSP_CHAIN_H

#include "ewsp_types.h"
#include "ewsp_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Chain State
 * ============================================================================ */

/**
 * @brief Single-direction chain state.
 * 
 * Tracks sequence number and hash of last packet in one direction.
 */
typedef struct {
    ewsp_seq_t sequence;                    /**< Current sequence number */
    char last_hash[EWSP_HASH_HEX_SIZE];    /**< Hash of last packet (hex) */
} ewsp_chain_state_t;

/**
 * @brief Initialize chain state to genesis.
 * 
 * Sets sequence to 0 and last_hash to GENESIS_HASH (64 zeros).
 */
void ewsp_chain_init(ewsp_chain_state_t* chain);

/**
 * @brief Reset chain to genesis state.
 */
void ewsp_chain_reset(ewsp_chain_state_t* chain);

/**
 * @brief Check if chain is at genesis state.
 */
bool ewsp_chain_is_genesis(const ewsp_chain_state_t* chain);

/**
 * @brief Update chain with new packet.
 * 
 * Called after successfully sending or receiving a packet.
 * 
 * @param chain Chain to update.
 * @param new_seq New sequence number.
 * @param packet_hash Hash of the packet (64 hex chars).
 */
void ewsp_chain_update(ewsp_chain_state_t* chain, 
                       ewsp_seq_t new_seq, 
                       const char* packet_hash);

/* ============================================================================
 * Bidirectional Chain Context
 * ============================================================================ */

/**
 * @brief Full bidirectional chain context.
 * 
 * Manages both TX (outgoing) and RX (incoming) chains.
 */
typedef struct {
    ewsp_chain_state_t tx;          /**< Outgoing chain state */
    ewsp_chain_state_t rx;          /**< Incoming chain state */
    char last_received_hash[EWSP_HASH_HEX_SIZE];  /**< Hash of last received packet */
    bool initialized;               /**< Context is ready */
} ewsp_chain_ctx_t;

/**
 * @brief Initialize bidirectional chain context.
 * 
 * Resets both chains to genesis state.
 */
void ewsp_chain_ctx_init(ewsp_chain_ctx_t* ctx);

/**
 * @brief Reset both chains to genesis.
 */
void ewsp_chain_ctx_reset(ewsp_chain_ctx_t* ctx);

/**
 * @brief Get next TX sequence number.
 * 
 * Returns current tx.sequence + 1 (the sequence for next outgoing packet).
 */
ewsp_seq_t ewsp_chain_next_tx_seq(const ewsp_chain_ctx_t* ctx);

/**
 * @brief Get current TX hash (prev_hash for next outgoing packet).
 */
const char* ewsp_chain_tx_hash(const ewsp_chain_ctx_t* ctx);

/**
 * @brief Get current RX hash (expected prev_hash for next incoming packet).
 */
const char* ewsp_chain_rx_hash(const ewsp_chain_ctx_t* ctx);

/**
 * @brief Get hash of last received packet (for response linking).
 */
const char* ewsp_chain_last_received_hash(const ewsp_chain_ctx_t* ctx);

/**
 * @brief Update TX chain after sending a packet.
 * 
 * @param ctx Chain context.
 * @param seq Sequence number of sent packet.
 * @param packet_hash Hash of sent packet.
 */
void ewsp_chain_update_tx(ewsp_chain_ctx_t* ctx, 
                          ewsp_seq_t seq, 
                          const char* packet_hash);

/**
 * @brief Update RX chain after receiving a packet.
 * 
 * @param ctx Chain context.
 * @param seq Sequence number of received packet.
 * @param packet_hash Hash of received packet.
 */
void ewsp_chain_update_rx(ewsp_chain_ctx_t* ctx,
                          ewsp_seq_t seq,
                          const char* packet_hash);

/* ============================================================================
 * Chain Validation
 * ============================================================================ */

/**
 * @brief Validate incoming packet chain fields.
 * 
 * Checks:
 * 1. Sequence > current rx.sequence (monotonic)
 * 2. prev_hash == rx.last_hash (chain continuity)
 * 3. Sequence jump not too large (DoS protection)
 * 
 * @param ctx Chain context.
 * @param seq Incoming packet sequence.
 * @param prev_hash Incoming packet prev_hash.
 * @return EWSP_OK if valid, error code otherwise.
 */
ewsp_error_t ewsp_chain_validate(const ewsp_chain_ctx_t* ctx,
                                  ewsp_seq_t seq,
                                  const char* prev_hash);

/**
 * @brief Maximum allowed sequence jump.
 * 
 * Prevents DoS where attacker sends packet with huge sequence number.
 */
#define EWSP_MAX_SEQ_JUMP 100

/* ============================================================================
 * Chain Hash Calculation
 * ============================================================================ */

/**
 * @brief Calculate SHA256 hash of packet string.
 * 
 * @param packet_json Full packet JSON string.
 * @param hash_hex_out Output buffer for hex hash (64 chars + null).
 */
void ewsp_chain_hash_packet(const char* packet_json, char hash_hex_out[65]);

/* ============================================================================
 * Chain Serialization (for persistence)
 * ============================================================================ */

/**
 * @brief Chain state for serialization.
 */
typedef struct {
    ewsp_seq_t tx_seq;
    char tx_hash[EWSP_HASH_HEX_SIZE];
    ewsp_seq_t rx_seq;
    char rx_hash[EWSP_HASH_HEX_SIZE];
} ewsp_chain_snapshot_t;

/**
 * @brief Export chain state for persistence.
 */
void ewsp_chain_export(const ewsp_chain_ctx_t* ctx, ewsp_chain_snapshot_t* snapshot);

/**
 * @brief Import chain state from persistence.
 */
void ewsp_chain_import(ewsp_chain_ctx_t* ctx, const ewsp_chain_snapshot_t* snapshot);

#ifdef __cplusplus
}
#endif

#endif /* EWSP_CHAIN_H */
