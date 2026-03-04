/**
 * @file ewsp_chain.c
 * @brief EWSP Core Library - Blockchain Chain Management Implementation
 * 
 * @author deadboizxc
 * @version 1.0
 */

#include "ewsp_chain.h"
#include "ewsp_crypto.h"
#include <string.h>

/* ============================================================================
 * Chain State Functions
 * ============================================================================ */

void ewsp_chain_init(ewsp_chain_state_t* chain) {
    if (!chain) return;
    
    chain->sequence = 0;
    strcpy(chain->last_hash, EWSP_GENESIS_HASH);
}

void ewsp_chain_reset(ewsp_chain_state_t* chain) {
    ewsp_chain_init(chain);
}

bool ewsp_chain_is_genesis(const ewsp_chain_state_t* chain) {
    if (!chain) return false;
    
    return (chain->sequence == 0) && 
           (strcmp(chain->last_hash, EWSP_GENESIS_HASH) == 0);
}

void ewsp_chain_update(ewsp_chain_state_t* chain, 
                       ewsp_seq_t new_seq, 
                       const char* packet_hash) {
    if (!chain || !packet_hash) return;
    
    chain->sequence = new_seq;
    
    /* Copy hash (truncate if necessary) */
    size_t len = strlen(packet_hash);
    if (len >= EWSP_HASH_HEX_SIZE) {
        len = EWSP_HASH_HEX_SIZE - 1;
    }
    memcpy(chain->last_hash, packet_hash, len);
    chain->last_hash[len] = '\0';
}

/* ============================================================================
 * Bidirectional Chain Context
 * ============================================================================ */

void ewsp_chain_ctx_init(ewsp_chain_ctx_t* ctx) {
    if (!ctx) return;
    
    ewsp_chain_init(&ctx->tx);
    ewsp_chain_init(&ctx->rx);
    strcpy(ctx->last_received_hash, EWSP_GENESIS_HASH);
    ctx->initialized = true;
}

void ewsp_chain_ctx_reset(ewsp_chain_ctx_t* ctx) {
    ewsp_chain_ctx_init(ctx);
}

ewsp_seq_t ewsp_chain_next_tx_seq(const ewsp_chain_ctx_t* ctx) {
    if (!ctx) return 0;
    return ctx->tx.sequence + 1;
}

const char* ewsp_chain_tx_hash(const ewsp_chain_ctx_t* ctx) {
    if (!ctx) return EWSP_GENESIS_HASH;
    return ctx->tx.last_hash;
}

const char* ewsp_chain_rx_hash(const ewsp_chain_ctx_t* ctx) {
    if (!ctx) return EWSP_GENESIS_HASH;
    return ctx->rx.last_hash;
}

const char* ewsp_chain_last_received_hash(const ewsp_chain_ctx_t* ctx) {
    if (!ctx) return EWSP_GENESIS_HASH;
    return ctx->last_received_hash;
}

void ewsp_chain_update_tx(ewsp_chain_ctx_t* ctx, 
                          ewsp_seq_t seq, 
                          const char* packet_hash) {
    if (!ctx) return;
    ewsp_chain_update(&ctx->tx, seq, packet_hash);
}

void ewsp_chain_update_rx(ewsp_chain_ctx_t* ctx,
                          ewsp_seq_t seq,
                          const char* packet_hash) {
    if (!ctx || !packet_hash) return;
    
    ewsp_chain_update(&ctx->rx, seq, packet_hash);
    
    /* Also update last_received_hash for response linking */
    size_t len = strlen(packet_hash);
    if (len >= EWSP_HASH_HEX_SIZE) {
        len = EWSP_HASH_HEX_SIZE - 1;
    }
    memcpy(ctx->last_received_hash, packet_hash, len);
    ctx->last_received_hash[len] = '\0';
}

/* ============================================================================
 * Chain Validation
 * ============================================================================ */

ewsp_error_t ewsp_chain_validate(const ewsp_chain_ctx_t* ctx,
                                  ewsp_seq_t seq,
                                  const char* prev_hash) {
    if (!ctx || !prev_hash) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    /* Check sequence is monotonically increasing */
    if (seq <= ctx->rx.sequence) {
        return EWSP_ERR_REPLAY_DETECTED;
    }
    
    /* Check sequence doesn't jump too far (DoS protection) */
    if (seq > ctx->rx.sequence + EWSP_MAX_SEQ_JUMP) {
        return EWSP_ERR_SEQ_JUMP_TOO_LARGE;
    }
    
    /* CRYPTO-05 FIX: Constant-time comparison to prevent timing attacks */
    size_t prev_len = strlen(prev_hash);
    size_t expected_len = strlen(ctx->rx.last_hash);
    
    if (prev_len != expected_len) {
        return EWSP_ERR_CHAIN_BROKEN;
    }
    
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < prev_len; i++) {
        diff |= (uint8_t)(prev_hash[i] ^ ctx->rx.last_hash[i]);
    }
    
    if (diff != 0) {
        return EWSP_ERR_CHAIN_BROKEN;
    }
    
    return EWSP_OK;
}

/* ============================================================================
 * Chain Hash Calculation
 * ============================================================================ */

void ewsp_chain_hash_packet(const char* packet_json, char hash_hex_out[65]) {
    if (!packet_json || !hash_hex_out) {
        if (hash_hex_out) {
            strcpy(hash_hex_out, EWSP_GENESIS_HASH);
        }
        return;
    }
    
    /* Calculate SHA256 of packet JSON string */
    uint8_t hash[32];
    ewsp_sha256((const uint8_t*)packet_json, strlen(packet_json), hash);
    
    /* Convert to hex */
    ewsp_bytes_to_hex(hash, 32, hash_hex_out);
}

/* ============================================================================
 * Chain Serialization
 * ============================================================================ */

void ewsp_chain_export(const ewsp_chain_ctx_t* ctx, ewsp_chain_snapshot_t* snapshot) {
    if (!ctx || !snapshot) return;
    
    snapshot->tx_seq = ctx->tx.sequence;
    strcpy(snapshot->tx_hash, ctx->tx.last_hash);
    snapshot->rx_seq = ctx->rx.sequence;
    strcpy(snapshot->rx_hash, ctx->rx.last_hash);
}

void ewsp_chain_import(ewsp_chain_ctx_t* ctx, const ewsp_chain_snapshot_t* snapshot) {
    if (!ctx || !snapshot) return;
    
    ctx->tx.sequence = snapshot->tx_seq;
    strcpy(ctx->tx.last_hash, snapshot->tx_hash);
    ctx->rx.sequence = snapshot->rx_seq;
    strcpy(ctx->rx.last_hash, snapshot->rx_hash);
    strcpy(ctx->last_received_hash, snapshot->rx_hash);
    ctx->initialized = true;
}
