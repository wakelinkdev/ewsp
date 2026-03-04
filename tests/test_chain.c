/**
 * @file test_chain.c
 * @brief EWSP Core Library - Chain Tests
 */

#include <stdio.h>
#include <string.h>
#include "ewsp.h"

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s\n", msg); \
        return 1; \
    } \
} while(0)

#define TEST_PASS(name) printf("  PASS: %s\n", name)

/* Test chain init */
static int test_chain_init(void) {
    ewsp_chain_ctx_t ctx;
    ewsp_chain_ctx_init(&ctx);
    
    TEST_ASSERT(ctx.tx.sequence == 0, "TX seq should be 0");
    TEST_ASSERT(ctx.rx.sequence == 0, "RX seq should be 0");
    TEST_ASSERT(strcmp(ctx.tx.last_hash, EWSP_GENESIS_HASH) == 0, "TX hash should be genesis");
    TEST_ASSERT(strcmp(ctx.rx.last_hash, EWSP_GENESIS_HASH) == 0, "RX hash should be genesis");
    
    TEST_PASS("Chain init");
    return 0;
}

/* Test TX chain progression */
static int test_chain_tx(void) {
    ewsp_chain_ctx_t ctx;
    ewsp_chain_ctx_init(&ctx);
    
    /* First TX */
    ewsp_seq_t seq1 = ewsp_chain_next_tx_seq(&ctx);
    TEST_ASSERT(seq1 == 1, "First seq should be 1");
    
    const char* hash1 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    ewsp_chain_update_tx(&ctx, seq1, hash1);
    
    TEST_ASSERT(ctx.tx.sequence == 1, "TX seq should be 1");
    TEST_ASSERT(strcmp(ctx.tx.last_hash, hash1) == 0, "TX hash should be updated");
    
    /* Second TX */
    ewsp_seq_t seq2 = ewsp_chain_next_tx_seq(&ctx);
    TEST_ASSERT(seq2 == 2, "Second seq should be 2");
    
    const char* hash2 = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    ewsp_chain_update_tx(&ctx, seq2, hash2);
    
    TEST_ASSERT(ctx.tx.sequence == 2, "TX seq should be 2");
    TEST_ASSERT(strcmp(ctx.tx.last_hash, hash2) == 0, "TX hash should be updated");
    
    TEST_PASS("Chain TX progression");
    return 0;
}

/* Test RX chain validation */
static int test_chain_rx_validation(void) {
    ewsp_chain_ctx_t ctx;
    ewsp_chain_ctx_init(&ctx);
    
    /* Valid first packet (seq=1, prev=genesis) */
    ewsp_error_t err = ewsp_chain_validate(&ctx, 1, EWSP_GENESIS_HASH);
    TEST_ASSERT(err == EWSP_OK, "First packet should be valid");
    
    /* Update RX with hash */
    const char* hash1 = "aaaa000000000000000000000000000000000000000000000000000000000000";
    ewsp_chain_update_rx(&ctx, 1, hash1);
    
    /* Valid second packet (seq=2, prev=hash1) */
    err = ewsp_chain_validate(&ctx, 2, hash1);
    TEST_ASSERT(err == EWSP_OK, "Second packet should be valid");
    
    /* Replay attack (seq=1 again) */
    err = ewsp_chain_validate(&ctx, 1, EWSP_GENESIS_HASH);
    TEST_ASSERT(err == EWSP_ERR_REPLAY_DETECTED, "Replay should be detected");
    
    /* Broken chain (wrong prev_hash) */
    err = ewsp_chain_validate(&ctx, 3, "wrong_hash_here");
    TEST_ASSERT(err == EWSP_ERR_CHAIN_BROKEN, "Broken chain should be detected");
    
    TEST_PASS("Chain RX validation");
    return 0;
}

/* Test chain hash calculation */
static int test_chain_hash(void) {
    const char* packet = "{\"v\":\"1.0\",\"id\":\"WL12345678\",\"seq\":1,\"prev\":\"genesis\",\"p\":\"abc123\",\"sig\":\"def456\"}";
    
    char hash[65];
    ewsp_chain_hash_packet(packet, hash);
    
    TEST_ASSERT(strlen(hash) == 64, "Hash should be 64 hex chars");
    
    /* Same packet should produce same hash */
    char hash2[65];
    ewsp_chain_hash_packet(packet, hash2);
    TEST_ASSERT(strcmp(hash, hash2) == 0, "Same packet should produce same hash");
    
    /* Different packet should produce different hash */
    const char* packet2 = "{\"v\":\"1.0\",\"id\":\"WL12345678\",\"seq\":2,\"prev\":\"genesis\",\"p\":\"abc123\",\"sig\":\"def456\"}";
    char hash3[65];
    ewsp_chain_hash_packet(packet2, hash3);
    TEST_ASSERT(strcmp(hash, hash3) != 0, "Different packets should produce different hashes");
    
    TEST_PASS("Chain hash calculation");
    return 0;
}

/* Test chain export/import */
static int test_chain_persistence(void) {
    ewsp_chain_ctx_t ctx1;
    ewsp_chain_ctx_init(&ctx1);
    
    /* Make some updates */
    ewsp_seq_t seq = ewsp_chain_next_tx_seq(&ctx1);
    ewsp_chain_update_tx(&ctx1, seq, "tx_hash_1234567890123456789012345678901234567890123456789012");
    ewsp_chain_update_rx(&ctx1, 5, "rx_hash_1234567890123456789012345678901234567890123456789012");
    
    /* Export */
    ewsp_chain_snapshot_t snapshot;
    ewsp_chain_export(&ctx1, &snapshot);
    
    TEST_ASSERT(snapshot.tx_seq == 1, "Exported TX seq wrong");
    TEST_ASSERT(snapshot.rx_seq == 5, "Exported RX seq wrong");
    
    /* Import into new context */
    ewsp_chain_ctx_t ctx2;
    ewsp_chain_ctx_init(&ctx2);
    ewsp_chain_import(&ctx2, &snapshot);
    
    TEST_ASSERT(ctx2.tx.sequence == ctx1.tx.sequence, "TX seq not restored");
    TEST_ASSERT(ctx2.rx.sequence == ctx1.rx.sequence, "RX seq not restored");
    TEST_ASSERT(strcmp(ctx2.tx.last_hash, ctx1.tx.last_hash) == 0, "TX hash not restored");
    TEST_ASSERT(strcmp(ctx2.rx.last_hash, ctx1.rx.last_hash) == 0, "RX hash not restored");
    
    TEST_PASS("Chain persistence");
    return 0;
}

/* Test chain reset */
static int test_chain_reset(void) {
    ewsp_chain_ctx_t ctx;
    ewsp_chain_ctx_init(&ctx);
    
    /* Make some updates */
    ewsp_chain_update_tx(&ctx, 10, "some_hash_12345678901234567890123456789012345678901234567890");
    ewsp_chain_update_rx(&ctx, 20, "other_hash_1234567890123456789012345678901234567890123456789");
    
    /* Reset */
    ewsp_chain_ctx_reset(&ctx);
    
    TEST_ASSERT(ctx.tx.sequence == 0, "TX seq should be 0 after reset");
    TEST_ASSERT(ctx.rx.sequence == 0, "RX seq should be 0 after reset");
    TEST_ASSERT(strcmp(ctx.tx.last_hash, EWSP_GENESIS_HASH) == 0, "TX hash should be genesis after reset");
    TEST_ASSERT(strcmp(ctx.rx.last_hash, EWSP_GENESIS_HASH) == 0, "RX hash should be genesis after reset");
    
    TEST_PASS("Chain reset");
    return 0;
}

int test_chain_all(void) {
    int result = 0;
    
    result |= test_chain_init();
    result |= test_chain_tx();
    result |= test_chain_rx_validation();
    result |= test_chain_hash();
    result |= test_chain_persistence();
    result |= test_chain_reset();
    
    return result;
}
