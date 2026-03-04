/**
 * @file test_packet.c
 * @brief EWSP Core Library - Packet Tests
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

/* Test packet context lifecycle */
static int test_packet_ctx(void) {
    ewsp_packet_ctx ctx;
    const char* token = "test_token_32_characters_minimum";
    const char* device_id = "WL12345678";
    
    ewsp_error_t err = ewsp_packet_init(&ctx, token, device_id);
    TEST_ASSERT(err == EWSP_OK, "Packet init failed");
    TEST_ASSERT(ctx.initialized, "Packet not marked as initialized");
    TEST_ASSERT(strcmp(ctx.device_id, device_id) == 0, "Device ID mismatch");
    
    ewsp_packet_cleanup(&ctx);
    TEST_ASSERT(!ctx.initialized, "Packet not cleaned up");
    
    TEST_PASS("Packet context lifecycle");
    return 0;
}

/* Test create command packet */
static int test_create_command(void) {
    ewsp_packet_ctx ctx;
    const char* token = "test_token_32_characters_minimum";
    const char* device_id = "WL12345678";
    
    ewsp_error_t err = ewsp_packet_init(&ctx, token, device_id);
    TEST_ASSERT(err == EWSP_OK, "Packet init failed");
    
    /* Create ping command */
    char packet[2048];
    err = ewsp_packet_create_command(&ctx, "ping", NULL, packet, sizeof(packet));
    TEST_ASSERT(err == EWSP_OK, "Create command failed");
    
    /* Verify packet structure */
    TEST_ASSERT(strstr(packet, "\"v\":\"1.0\"") != NULL, "Missing version");
    TEST_ASSERT(strstr(packet, "\"id\":\"WL12345678\"") != NULL, "Missing device_id");
    TEST_ASSERT(strstr(packet, "\"seq\":1") != NULL, "Missing sequence");
    TEST_ASSERT(strstr(packet, "\"prev\":\"genesis\"") != NULL, "Missing prev_hash");
    TEST_ASSERT(strstr(packet, "\"p\":") != NULL, "Missing payload");
    TEST_ASSERT(strstr(packet, "\"sig\":") != NULL, "Missing signature");
    
    ewsp_packet_cleanup(&ctx);
    TEST_PASS("Create command packet");
    return 0;
}

/* Test create command with data */
static int test_create_command_with_data(void) {
    ewsp_packet_ctx ctx;
    const char* token = "test_token_32_characters_minimum";
    const char* device_id = "WL12345678";
    
    ewsp_error_t err = ewsp_packet_init(&ctx, token, device_id);
    TEST_ASSERT(err == EWSP_OK, "Packet init failed");
    
    /* Create wake command */
    char packet[2048];
    err = ewsp_packet_create_command(&ctx, "wake", "{\"mac\":\"AA:BB:CC:DD:EE:FF\"}", packet, sizeof(packet));
    TEST_ASSERT(err == EWSP_OK, "Create wake command failed");
    
    /* Packet should contain encrypted payload */
    TEST_ASSERT(strstr(packet, "\"p\":") != NULL, "Missing payload");
    
    ewsp_packet_cleanup(&ctx);
    TEST_PASS("Create command with data");
    return 0;
}

/* Test parse outer packet */
static int test_parse_outer(void) {
    const char* packet = "{\"v\":\"1.0\",\"id\":\"WL12345678\",\"seq\":42,\"prev\":\"genesis\",\"p\":\"0123abcd\",\"sig\":\"deadbeef\"}";
    
    ewsp_outer_packet_t outer;
    ewsp_error_t err = ewsp_packet_parse_outer(packet, &outer);
    TEST_ASSERT(err == EWSP_OK, "Parse failed");
    
    TEST_ASSERT(strcmp(outer.version, "1.0") == 0, "Wrong version");
    TEST_ASSERT(strcmp(outer.device_id, "WL12345678") == 0, "Wrong device_id");
    TEST_ASSERT(outer.sequence == 42, "Wrong sequence");
    TEST_ASSERT(strcmp(outer.prev_hash, "genesis") == 0, "Wrong prev_hash");
    TEST_ASSERT(strcmp(outer.payload, "0123abcd") == 0, "Wrong payload");
    TEST_ASSERT(strcmp(outer.signature, "deadbeef") == 0, "Wrong signature");
    
    TEST_PASS("Parse outer packet");
    return 0;
}

/* Test full roundtrip: create -> process */
static int test_packet_roundtrip(void) {
    const char* token = "test_token_32_characters_minimum";
    const char* device_id = "WL12345678";
    
    /* Create sender context */
    ewsp_packet_ctx sender;
    ewsp_error_t err = ewsp_packet_init(&sender, token, device_id);
    TEST_ASSERT(err == EWSP_OK, "Sender init failed");
    
    /* Create packet */
    char packet[2048];
    err = ewsp_packet_create_command(&sender, "ping", NULL, packet, sizeof(packet));
    TEST_ASSERT(err == EWSP_OK, "Create command failed");
    
    /* Create receiver context */
    ewsp_packet_ctx receiver;
    err = ewsp_packet_init(&receiver, token, device_id);
    TEST_ASSERT(err == EWSP_OK, "Receiver init failed");
    
    /* Process packet */
    ewsp_packet_result_t result;
    err = ewsp_packet_process(&receiver, packet, &result);
    TEST_ASSERT(err == EWSP_OK, "Process failed");
    TEST_ASSERT(result.error == EWSP_OK, "Result has error");
    
    /* Verify decrypted command */
    TEST_ASSERT(strcmp(result.command, "ping") == 0, "Wrong command");
    TEST_ASSERT(strlen(result.request_id) == 8, "Wrong request_id length");
    TEST_ASSERT(result.is_response == false, "Should not be response");
    
    ewsp_packet_cleanup(&sender);
    ewsp_packet_cleanup(&receiver);
    TEST_PASS("Packet roundtrip");
    return 0;
}

/* Test signature verification failure */
static int test_signature_failure(void) {
    const char* token = "test_token_32_characters_minimum";
    const char* device_id = "WL12345678";
    
    /* Create sender context */
    ewsp_packet_ctx sender;
    ewsp_packet_init(&sender, token, device_id);
    
    char packet[2048];
    ewsp_packet_create_command(&sender, "ping", NULL, packet, sizeof(packet));
    
    /* Create receiver with DIFFERENT token */
    ewsp_packet_ctx receiver;
    ewsp_packet_init(&receiver, "different_token_that_is_32_chars", device_id);
    
    /* Process should fail signature verification */
    ewsp_packet_result_t result;
    ewsp_error_t err = ewsp_packet_process(&receiver, packet, &result);
    TEST_ASSERT(err == EWSP_ERR_INVALID_SIGNATURE, "Should fail signature check");
    
    ewsp_packet_cleanup(&sender);
    ewsp_packet_cleanup(&receiver);
    TEST_PASS("Signature failure detection");
    return 0;
}

/* Test chain state export/import */
static int test_chain_state_persistence(void) {
    const char* token = "test_token_32_characters_minimum";
    const char* device_id = "WL12345678";
    
    /* Create context and send some packets */
    ewsp_packet_ctx ctx1;
    ewsp_packet_init(&ctx1, token, device_id);
    
    char packet1[2048], packet2[2048];
    ewsp_packet_create_command(&ctx1, "ping", NULL, packet1, sizeof(packet1));
    ewsp_packet_create_command(&ctx1, "info", NULL, packet2, sizeof(packet2));
    
    /* Export state */
    ewsp_chain_snapshot_t snapshot;
    ewsp_packet_export_state(&ctx1, &snapshot);
    
    TEST_ASSERT(snapshot.tx_seq == 2, "Wrong TX sequence in snapshot");
    
    /* Create new context and import state */
    ewsp_packet_ctx ctx2;
    ewsp_packet_init(&ctx2, token, device_id);
    ewsp_packet_import_state(&ctx2, &snapshot);
    
    /* Next packet should have seq=3 */
    char packet3[2048];
    ewsp_packet_create_command(&ctx2, "restart", NULL, packet3, sizeof(packet3));
    TEST_ASSERT(strstr(packet3, "\"seq\":3") != NULL, "Wrong sequence after import");
    
    ewsp_packet_cleanup(&ctx1);
    ewsp_packet_cleanup(&ctx2);
    TEST_PASS("Chain state persistence");
    return 0;
}

/* Test request ID generation */
static int test_rid_generation(void) {
    char rid1[9], rid2[9];
    
    ewsp_packet_generate_rid(rid1);
    ewsp_packet_generate_rid(rid2);
    
    TEST_ASSERT(strlen(rid1) == 8, "RID1 wrong length");
    TEST_ASSERT(strlen(rid2) == 8, "RID2 wrong length");
    TEST_ASSERT(strcmp(rid1, rid2) != 0, "RIDs should be unique");
    
    /* Check all chars are alphanumeric uppercase */
    for (int i = 0; i < 8; i++) {
        char c = rid1[i];
        TEST_ASSERT((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'), "RID contains invalid char");
    }
    
    TEST_PASS("Request ID generation");
    return 0;
}

int test_packet_all(void) {
    int result = 0;
    
    result |= test_packet_ctx();
    result |= test_create_command();
    result |= test_create_command_with_data();
    result |= test_parse_outer();
    result |= test_packet_roundtrip();
    result |= test_signature_failure();
    result |= test_chain_state_persistence();
    result |= test_rid_generation();
    
    return result;
}
