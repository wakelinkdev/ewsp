/**
 * @file test_models.c
 * @brief Unit tests for ewsp_models module
 * 
 * Tests data model initialization and manipulation functions.
 * 
 * @version 1.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ewsp_models.h"
#include "ewsp_errors.h"
#include "ewsp_types.h"
#include "ewsp_chain.h"

/* ============================================================================
 * Test Counters
 * ============================================================================ */

static int tests_run = 0;
static int tests_passed = 0;

#define TEST_ASSERT(cond, msg) do { \
    tests_run++; \
    if (!(cond)) { \
        printf("  [FAIL] %s: %s\n", __func__, msg); \
        return 0; \
    } \
    tests_passed++; \
} while(0)

#define TEST_ASSERT_EQ(a, b, msg) TEST_ASSERT((a) == (b), msg)
#define TEST_ASSERT_STR_EQ(a, b, msg) TEST_ASSERT(strcmp((a), (b)) == 0, msg)
#define TEST_ASSERT_OK(err) TEST_ASSERT((err) == EWSP_OK, "Expected EWSP_OK")

/* ============================================================================
 * Device Info Tests
 * ============================================================================ */

static int test_device_info_init(void) {
    printf("  Testing ewsp_device_info_init...\n");
    
    ewsp_device_info_t info;
    
    /* Initialize with garbage first */
    memset(&info, 0xFF, sizeof(info));
    
    ewsp_device_info_init(&info);
    
    /* Check defaults */
    TEST_ASSERT_EQ(strlen(info.device_id), 0, "device_id empty");
    TEST_ASSERT_EQ(strlen(info.firmware_version), 0, "firmware_version empty");
    TEST_ASSERT_STR_EQ(info.protocol_version, "1.0", "protocol_version default");
    TEST_ASSERT_EQ(strlen(info.ip_address), 0, "ip_address empty");
    TEST_ASSERT_EQ(strlen(info.mac_address), 0, "mac_address empty");
    TEST_ASSERT_EQ(info.uptime_seconds, 0, "uptime_seconds zero");
    TEST_ASSERT_EQ(info.wifi_rssi, 0, "wifi_rssi zero");
    TEST_ASSERT_EQ(info.free_heap, 0, "free_heap zero");
    TEST_ASSERT_EQ(info.request_counter, 0, "request_counter zero");
    TEST_ASSERT(!info.cloud_connected, "cloud_connected false");
    TEST_ASSERT(!info.web_server_enabled, "web_server_enabled false");
    TEST_ASSERT(!info.ota_enabled, "ota_enabled false");
    
    return 1;
}

static int test_device_info_fields(void) {
    printf("  Testing device_info field sizes...\n");
    
    ewsp_device_info_t info;
    ewsp_device_info_init(&info);
    
    /* Test that fields can hold expected data */
    strncpy(info.device_id, "wakelink_device_001", EWSP_MAX_DEVICE_ID_LEN);
    info.device_id[EWSP_MAX_DEVICE_ID_LEN] = '\0';
    TEST_ASSERT(strlen(info.device_id) > 0, "device_id set");
    
    strcpy(info.firmware_version, "1.0.0");
    TEST_ASSERT_STR_EQ(info.firmware_version, "1.0.0", "firmware set");
    
    strcpy(info.protocol_version, "1.0");
    TEST_ASSERT_STR_EQ(info.protocol_version, "1.0", "protocol set");
    
    strcpy(info.ip_address, "192.168.1.100");
    TEST_ASSERT_STR_EQ(info.ip_address, "192.168.1.100", "ip set");
    
    strcpy(info.mac_address, "AA:BB:CC:DD:EE:FF");
    TEST_ASSERT_STR_EQ(info.mac_address, "AA:BB:CC:DD:EE:FF", "mac set");
    
    info.uptime_seconds = 86400;
    TEST_ASSERT_EQ(info.uptime_seconds, 86400, "uptime set");
    
    info.wifi_rssi = -55;
    TEST_ASSERT_EQ(info.wifi_rssi, -55, "rssi set");
    
    info.free_heap = 45000;
    TEST_ASSERT_EQ(info.free_heap, 45000, "heap set");
    
    info.request_counter = 1000000ULL;
    TEST_ASSERT_EQ(info.request_counter, 1000000ULL, "counter set");
    
    info.cloud_connected = true;
    info.web_server_enabled = true;
    info.ota_enabled = true;
    TEST_ASSERT(info.cloud_connected, "cloud_connected true");
    TEST_ASSERT(info.web_server_enabled, "web_server_enabled true");
    TEST_ASSERT(info.ota_enabled, "ota_enabled true");
    
    return 1;
}

/* ============================================================================
 * Inner Packet Tests
 * ============================================================================ */

static int test_inner_packet_init(void) {
    printf("  Testing ewsp_inner_packet_init...\n");
    
    ewsp_inner_packet_t pkt;
    
    /* Initialize with garbage */
    memset(&pkt, 0xFF, sizeof(pkt));
    
    ewsp_inner_packet_init(&pkt);
    
    /* Check defaults */
    TEST_ASSERT_EQ(strlen(pkt.command), 0, "cmd empty");
    TEST_ASSERT_EQ(strlen(pkt.request_id), 0, "rid empty");
    
    return 1;
}

static int test_inner_packet_set_command(void) {
    printf("  Testing ewsp_inner_packet_set_command...\n");
    
    ewsp_inner_packet_t pkt;
    ewsp_inner_packet_init(&pkt);
    
    /* Set normal command */
    ewsp_inner_packet_set_command(&pkt, "ping");
    TEST_ASSERT_STR_EQ(pkt.command, "ping", "ping command set");
    
    ewsp_inner_packet_set_command(&pkt, "wake");
    TEST_ASSERT_STR_EQ(pkt.command, "wake", "wake command set");
    
    ewsp_inner_packet_set_command(&pkt, "get_config");
    TEST_ASSERT_STR_EQ(pkt.command, "get_config", "get_config command set");
    
    /* Empty command */
    ewsp_inner_packet_set_command(&pkt, "");
    TEST_ASSERT_EQ(strlen(pkt.command), 0, "empty command");
    
    return 1;
}

static int test_inner_packet_set_rid(void) {
    printf("  Testing ewsp_inner_packet_set_rid...\n");
    
    ewsp_inner_packet_t pkt;
    ewsp_inner_packet_init(&pkt);
    
    /* Set normal rid */
    ewsp_inner_packet_set_rid(&pkt, "abc123");
    TEST_ASSERT_STR_EQ(pkt.request_id, "abc123", "rid set");
    
    /* Set max length rid */
    char long_rid[EWSP_REQUEST_ID_LEN + 10];
    memset(long_rid, 'x', sizeof(long_rid) - 1);
    long_rid[sizeof(long_rid) - 1] = '\0';
    
    ewsp_inner_packet_set_rid(&pkt, long_rid);
    TEST_ASSERT(strlen(pkt.request_id) <= EWSP_REQUEST_ID_LEN, "rid truncated to max");
    
    return 1;
}

static int test_inner_packet_generate_rid(void) {
    printf("  Testing ewsp_inner_packet_generate_rid...\n");
    
    ewsp_inner_packet_t pkt1, pkt2;
    ewsp_inner_packet_init(&pkt1);
    ewsp_inner_packet_init(&pkt2);
    
    /* Generate rids */
    ewsp_inner_packet_generate_rid(&pkt1);
    ewsp_inner_packet_generate_rid(&pkt2);
    
    /* Both should have rids */
    TEST_ASSERT(strlen(pkt1.request_id) > 0, "pkt1 rid generated");
    TEST_ASSERT(strlen(pkt2.request_id) > 0, "pkt2 rid generated");
    
    /* Rids should be different (with very high probability) */
    TEST_ASSERT(strcmp(pkt1.request_id, pkt2.request_id) != 0, "rids are unique");
    
    return 1;
}

/* ============================================================================
 * Wake Data Tests
 * ============================================================================ */

static int test_wake_data_struct(void) {
    printf("  Testing ewsp_wake_data_t...\n");
    
    ewsp_wake_data_t wake;
    
    memset(&wake, 0, sizeof(wake));
    
    /* Set MAC */
    strcpy(wake.mac, "AA:BB:CC:DD:EE:FF");
    TEST_ASSERT_STR_EQ(wake.mac, "AA:BB:CC:DD:EE:FF", "MAC set");
    
    /* Set port */
    wake.port = 9;
    TEST_ASSERT_EQ(wake.port, 9, "port set to 9");
    
    wake.port = 7;
    TEST_ASSERT_EQ(wake.port, 7, "port set to 7");
    
    /* Set broadcast */
    strcpy(wake.broadcast, "255.255.255.255");
    TEST_ASSERT_STR_EQ(wake.broadcast, "255.255.255.255", "broadcast set");
    
    return 1;
}

/* ============================================================================
 * WiFi Config Tests
 * ============================================================================ */

static int test_wifi_config_struct(void) {
    printf("  Testing ewsp_wifi_config_t...\n");
    
    ewsp_wifi_config_t wifi;
    
    memset(&wifi, 0, sizeof(wifi));
    
    /* Set SSID */
    strcpy(wifi.ssid, "MyNetwork");
    TEST_ASSERT_STR_EQ(wifi.ssid, "MyNetwork", "SSID set");
    
    /* Set password */
    strcpy(wifi.password, "SecurePassword123!");
    TEST_ASSERT_STR_EQ(wifi.password, "SecurePassword123!", "password set");
    
    /* Test max length SSID (32 chars) */
    memset(wifi.ssid, 'A', 32);
    wifi.ssid[32] = '\0';
    TEST_ASSERT_EQ(strlen(wifi.ssid), 32, "max SSID length");
    
    /* Test max length password (64 chars) */
    memset(wifi.password, 'B', 64);
    wifi.password[64] = '\0';
    TEST_ASSERT_EQ(strlen(wifi.password), 64, "max password length");
    
    return 1;
}

/* ============================================================================
 * Cloud Config Tests
 * ============================================================================ */

static int test_cloud_config_struct(void) {
    printf("  Testing ewsp_cloud_config_t...\n");
    
    ewsp_cloud_config_t cloud;
    
    memset(&cloud, 0, sizeof(cloud));
    
    /* Set URL */
    strcpy(cloud.url, "https://cloud.wakelink.example.com/api/v2");
    TEST_ASSERT(strstr(cloud.url, "wakelink") != NULL, "URL set");
    
    /* Set API token */
    strcpy(cloud.api_token, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...");
    TEST_ASSERT(strlen(cloud.api_token) > 10, "token set");
    
    /* Set enabled */
    cloud.enabled = true;
    TEST_ASSERT(cloud.enabled, "enabled true");
    
    cloud.enabled = false;
    TEST_ASSERT(!cloud.enabled, "enabled false");
    
    return 1;
}

/* ============================================================================
 * Response Structure Tests
 * ============================================================================ */

static int test_response_struct(void) {
    printf("  Testing ewsp_response_t...\n");
    
    ewsp_response_t resp;
    
    memset(&resp, 0, sizeof(resp));
    
    /* Set status */
    resp.success = true;
    TEST_ASSERT(resp.success, "status ok");
    
    resp.success = false;
    TEST_ASSERT(!resp.success, "status error");
    
    /* Set rid */
    strcpy(resp.request_id, "req12345");
    TEST_ASSERT_STR_EQ(resp.request_id, "req12345", "rid set");
    
    /* Set error code */
    resp.error_code = EWSP_ERR_AUTH_FAILED;
    TEST_ASSERT_EQ(resp.error_code, EWSP_ERR_AUTH_FAILED, "error_code set");
    
    return 1;
}

/* ============================================================================
 * Chain State Tests
 * ============================================================================ */

static int test_chain_state_struct(void) {
    printf("  Testing ewsp_chain_state_t...\n");
    
    ewsp_chain_state_t chain;
    
    memset(&chain, 0, sizeof(chain));
    
    /* Set sequence */
    chain.sequence = 42;
    TEST_ASSERT_EQ(chain.sequence, 42, "seq set");
    
    /* Set prev_hash */
    memset(chain.last_hash, 0xAB, 32);
    TEST_ASSERT_EQ((unsigned char)chain.last_hash[0], 0xAB, "prev_hash[0]");
    TEST_ASSERT_EQ((unsigned char)chain.last_hash[31], 0xAB, "prev_hash[31]");
    
    /* Max sequence */
    chain.sequence = 0xFFFFFFFF;
    TEST_ASSERT_EQ(chain.sequence, 0xFFFFFFFF, "max seq");
    
    return 1;
}

/* ============================================================================
 * Outer Packet Tests  
 * ============================================================================ */

static int test_outer_packet_struct(void) {
    printf("  Testing ewsp_outer_packet_t...\n");
    
    ewsp_outer_packet_t outer;
    
    memset(&outer, 0, sizeof(outer));
    
    /* Set version */
    strncpy(outer.version, "1.0", sizeof(outer.version));
    TEST_ASSERT_STR_EQ(outer.version, "1.0", "version 1.0");
    
    /* Set device_id */
    strcpy(outer.device_id, "wl_device_01");
    TEST_ASSERT_STR_EQ(outer.device_id, "wl_device_01", "device_id set");
    
    /* Set sequence */
    outer.sequence = 100;
    TEST_ASSERT_EQ(outer.sequence, 100, "seq set");
    
    /* Set signature (hex string, 64 chars + null) */
    memset(outer.signature, 'a', 64);
    outer.signature[64] = '\0';
    TEST_ASSERT_EQ(outer.signature[0], 'a', "sig[0]");
    TEST_ASSERT_EQ(outer.signature[63], 'a', "sig[63]");
    
    return 1;
}

/* ============================================================================
 * Test Runner
 * ============================================================================ */

int run_models_tests(void) {
    printf("\n=== EWSP Models Tests ===\n\n");
    
    tests_run = 0;
    tests_passed = 0;
    
    int all_passed = 1;
    
    /* Device info tests */
    if (!test_device_info_init()) all_passed = 0;
    if (!test_device_info_fields()) all_passed = 0;
    
    /* Inner packet tests */
    if (!test_inner_packet_init()) all_passed = 0;
    if (!test_inner_packet_set_command()) all_passed = 0;
    if (!test_inner_packet_set_rid()) all_passed = 0;
    if (!test_inner_packet_generate_rid()) all_passed = 0;
    
    /* Data structure tests */
    if (!test_wake_data_struct()) all_passed = 0;
    if (!test_wifi_config_struct()) all_passed = 0;
    if (!test_cloud_config_struct()) all_passed = 0;
    if (!test_response_struct()) all_passed = 0;
    if (!test_chain_state_struct()) all_passed = 0;
    if (!test_outer_packet_struct()) all_passed = 0;
    
    printf("\n--- Models Tests Summary ---\n");
    printf("Tests run: %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_run - tests_passed);
    printf("Result: %s\n\n", all_passed ? "PASS" : "FAIL");
    
    return all_passed ? 0 : 1;
}
