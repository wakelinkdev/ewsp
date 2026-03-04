/**
 * @file fuzz_packet.c
 * @brief AFL++ fuzzing harness for ewsp_packet module
 * 
 * Tests packet serialization/deserialization with malformed inputs:
 * - Invalid structures
 * - Boundary conditions
 * - Buffer overflows
 * - Integer overflows
 * 
 * Compile:
 *   afl-gcc -o fuzz_packet fuzz_packet.c -I../include -L../build -lewsp_core
 * 
 * Run:
 *   mkdir -p fuzz_input/packet fuzz_output/packet
 *   echo -n '{"v":"1.0","id":"WL12345678","seq":1,"prev":"0000","p":"{}","sig":"abc"}' > fuzz_input/packet/seed
 *   afl-fuzz -i fuzz_input/packet -o fuzz_output/packet ./fuzz_packet
 * 
 * @author deadboizxc
 * @version 1.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "ewsp_packet.h"
#include "ewsp_chain.h"
#include "ewsp_crypto.h"
#include "ewsp_errors.h"

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_FUZZ_INIT();
#endif

#define MAX_INPUT_SIZE 8192

/* Test key for packet operations */
static const uint8_t TEST_KEY[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};

/**
 * Fuzz outer packet parsing
 */
static void fuzz_parse_outer(const char* data, size_t len) {
    ewsp_outer_packet_t packet;
    
    ewsp_error_t err = ewsp_packet_parse_outer(data, &packet);
    if (err == EWSP_OK) {
        /* Access parsed fields to trigger potential issues */
        size_t sig_len = strlen(packet.device_id);
        (void)sig_len;
        (void)packet.version;
        (void)packet.seq;
    }
}

/**
 * Fuzz inner packet parsing
 */
static void fuzz_parse_inner(const char* data, size_t len) {
    ewsp_inner_packet_t packet;
    
    ewsp_error_t err = ewsp_packet_parse_inner(data, &packet);
    if (err == EWSP_OK) {
        size_t cmd_len = strlen(packet.cmd);
        size_t rid_len = strlen(packet.rid);
        (void)cmd_len;
        (void)rid_len;
        (void)packet.timestamp;
    }
}

/**
 * Fuzz packet signature verification
 */
static void fuzz_verify_signature(const char* data, size_t len) {
    ewsp_outer_packet_t packet;
    
    if (ewsp_packet_parse_outer(data, &packet) == EWSP_OK) {
        /* Try to verify with test key */
        ewsp_packet_verify_signature(&packet, TEST_KEY, 32);
    }
}

/**
 * Fuzz chain validation
 */
static void fuzz_chain_validate(const char* data, size_t len) {
    ewsp_outer_packet_t packet;
    
    if (ewsp_packet_parse_outer(data, &packet) == EWSP_OK) {
        ewsp_chain_state_t chain;
        ewsp_chain_init(&chain);
        
        /* Validate against genesis chain */
        ewsp_chain_validate(&chain, &packet);
    }
}

/**
 * Fuzz packet building with fuzzed values
 */
static void fuzz_build_outer(const uint8_t* data, size_t len) {
    if (len < 64) return;
    
    ewsp_outer_packet_t packet;
    ewsp_chain_state_t chain;
    char output[4096];
    
    ewsp_chain_init(&chain);
    
    /* Use fuzz data as device_id (first 32 bytes, null-terminated) */
    char device_id[33];
    size_t id_len = (len > 32) ? 32 : len;
    memcpy(device_id, data, id_len);
    device_id[id_len] = '\0';
    
    /* Use rest as payload */
    const char* payload = (const char*)(data + id_len);
    size_t payload_len = len - id_len;
    
    char safe_payload[1024];
    if (payload_len >= sizeof(safe_payload)) {
        payload_len = sizeof(safe_payload) - 1;
    }
    memcpy(safe_payload, payload, payload_len);
    safe_payload[payload_len] = '\0';
    
    ewsp_packet_build_outer(
        device_id,
        safe_payload,
        &chain,
        TEST_KEY, 32,
        &packet, output, sizeof(output)
    );
}

/**
 * Fuzz packet building with inner packet
 */
static void fuzz_build_inner(const uint8_t* data, size_t len) {
    if (len < 32) return;
    
    ewsp_inner_packet_t inner;
    char output[2048];
    
    ewsp_inner_packet_init(&inner);
    
    /* Use first 16 bytes as command */
    char cmd[17];
    memcpy(cmd, data, 16);
    cmd[16] = '\0';
    ewsp_inner_packet_set_command(&inner, cmd);
    
    /* Use next 16 bytes as rid */
    char rid[17];
    memcpy(rid, data + 16, 16);
    rid[16] = '\0';
    ewsp_inner_packet_set_rid(&inner, rid);
    
    ewsp_packet_build_inner(&inner, output, sizeof(output));
}

/**
 * Fuzz protocol v2 packet
 */
static void fuzz_protocol_v2(const char* data, size_t len) {
    /* Parse as v2 packet */
    ewsp_outer_packet_t outer;
    ewsp_inner_packet_t inner;
    ewsp_chain_state_t chain;
    
    ewsp_chain_init(&chain);
    
    if (ewsp_packet_parse_outer(data, &outer) == EWSP_OK) {
        /* Validate version */
        if (outer.version == 2) {
            /* Validate chain */
            ewsp_chain_validate(&chain, &outer);
            
            /* Try to decrypt and parse inner */
            char decrypted[4096];
            if (ewsp_packet_decrypt_payload(&outer, TEST_KEY, 32, decrypted, sizeof(decrypted)) == EWSP_OK) {
                ewsp_packet_parse_inner(decrypted, &inner);
            }
        }
    }
}

int main(int argc, char* argv[]) {
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
    
    uint8_t* buf = __AFL_FUZZ_TESTCASE_BUF;
    
    while (__AFL_LOOP(10000)) {
        size_t len = __AFL_FUZZ_TESTCASE_LEN;
        if (len > MAX_INPUT_SIZE) len = MAX_INPUT_SIZE;
        if (len == 0) continue;
        
        /* Null-terminate */
        char* data = malloc(len + 1);
        if (!data) continue;
        memcpy(data, buf, len);
        data[len] = '\0';
        
        /* Run fuzz targets */
        fuzz_parse_outer(data, len);
        fuzz_parse_inner(data, len);
        fuzz_verify_signature(data, len);
        fuzz_chain_validate(data, len);
        fuzz_build_outer(buf, len);
        fuzz_build_inner(buf, len);
        fuzz_protocol_v2(data, len);
        
        free(data);
    }
#else
    /* Non-AFL mode */
    char buf[MAX_INPUT_SIZE];
    size_t len = fread(buf, 1, MAX_INPUT_SIZE - 1, stdin);
    buf[len] = '\0';
    
    if (len > 0) {
        fuzz_parse_outer(buf, len);
        fuzz_parse_inner(buf, len);
        fuzz_verify_signature(buf, len);
        fuzz_chain_validate(buf, len);
        fuzz_build_outer((uint8_t*)buf, len);
        fuzz_build_inner((uint8_t*)buf, len);
        fuzz_protocol_v2(buf, len);
    }
#endif

    return 0;
}
