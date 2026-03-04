/**
 * @file test_commands.c
 * @brief Unit tests for ewsp_commands module
 * 
 * Tests command building, parsing, and MAC address utilities.
 * 
 * @version 1.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ewsp_commands.h"
#include "ewsp_errors.h"
#include "ewsp_models.h"

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
 * Command Type Tests
 * ============================================================================ */

static int test_cmd_from_name(void) {
    printf("  Testing ewsp_cmd_from_name...\n");
    
    TEST_ASSERT_EQ(ewsp_cmd_from_name(EWSP_CMD_PING), EWSP_CMD_TYPE_PING, "ping command");
    TEST_ASSERT_EQ(ewsp_cmd_from_name(EWSP_CMD_WAKE), EWSP_CMD_TYPE_WAKE, "wake command");
    TEST_ASSERT_EQ(ewsp_cmd_from_name(EWSP_CMD_INFO), EWSP_CMD_TYPE_INFO, "info command");
    TEST_ASSERT_EQ(ewsp_cmd_from_name(EWSP_CMD_RESTART), EWSP_CMD_TYPE_RESTART, "restart command");
    TEST_ASSERT_EQ(ewsp_cmd_from_name(EWSP_CMD_OTA_START), EWSP_CMD_TYPE_OTA_START, "ota_start command");
    TEST_ASSERT_EQ(ewsp_cmd_from_name(EWSP_CMD_OPEN_SETUP), EWSP_CMD_TYPE_OPEN_SETUP, "open_setup command");
    TEST_ASSERT_EQ(ewsp_cmd_from_name(EWSP_CMD_GET_CONFIG), EWSP_CMD_TYPE_GET_CONFIG, "get_config command");
    TEST_ASSERT_EQ(ewsp_cmd_from_name("unknown_cmd"), EWSP_CMD_TYPE_UNKNOWN, "unknown command");
    TEST_ASSERT_EQ(ewsp_cmd_from_name(NULL), EWSP_CMD_TYPE_UNKNOWN, "NULL command");
    TEST_ASSERT_EQ(ewsp_cmd_from_name(""), EWSP_CMD_TYPE_UNKNOWN, "empty command");
    
    return 1;
}

static int test_cmd_requires_data(void) {
    printf("  Testing ewsp_cmd_requires_data...\n");
    
    /* Commands without data */
    TEST_ASSERT(!ewsp_cmd_requires_data(EWSP_CMD_TYPE_PING), "ping no data");
    TEST_ASSERT(!ewsp_cmd_requires_data(EWSP_CMD_TYPE_INFO), "info no data");
    TEST_ASSERT(!ewsp_cmd_requires_data(EWSP_CMD_TYPE_RESTART), "restart no data");
    TEST_ASSERT(!ewsp_cmd_requires_data(EWSP_CMD_TYPE_GET_CONFIG), "get_config no data");
    
    /* Commands with data */
    TEST_ASSERT(ewsp_cmd_requires_data(EWSP_CMD_TYPE_WAKE), "wake needs data");
    TEST_ASSERT(ewsp_cmd_requires_data(EWSP_CMD_TYPE_SET_WIFI), "set_wifi needs data");
    TEST_ASSERT(ewsp_cmd_requires_data(EWSP_CMD_TYPE_SET_CLOUD), "set_cloud needs data");
    TEST_ASSERT(ewsp_cmd_requires_data(EWSP_CMD_TYPE_UPDATE_TOKEN), "update_token needs data");
    
    return 1;
}

/* ============================================================================
 * Command Building Tests
 * ============================================================================ */

static int test_cmd_build_ping(void) {
    printf("  Testing ewsp_cmd_build_ping...\n");
    
    char json[256];
    ewsp_error_t err;
    
    err = ewsp_cmd_build_ping(json, sizeof(json));
    TEST_ASSERT_OK(err);
    TEST_ASSERT(strstr(json, "\"cmd\"") != NULL, "has cmd field");
    TEST_ASSERT(strstr(json, "\"ping\"") != NULL, "has ping value");
    TEST_ASSERT(strstr(json, "\"rid\"") != NULL, "has rid field");
    
    /* Buffer too small */
    err = ewsp_cmd_build_ping(json, 5);
    TEST_ASSERT(err != EWSP_OK, "small buffer should fail");
    
    /* NULL buffer */
    err = ewsp_cmd_build_ping(NULL, 256);
    TEST_ASSERT(err != EWSP_OK, "NULL buffer should fail");
    
    return 1;
}

static int test_cmd_build_wake(void) {
    printf("  Testing ewsp_cmd_build_wake...\n");
    
    char json[512];
    ewsp_error_t err;
    
    err = ewsp_cmd_build_wake("AA:BB:CC:DD:EE:FF", json, sizeof(json));
    TEST_ASSERT_OK(err);
    TEST_ASSERT(strstr(json, "\"cmd\"") != NULL, "has cmd field");
    TEST_ASSERT(strstr(json, "\"wake\"") != NULL, "has wake value");
    TEST_ASSERT(strstr(json, "AA:BB:CC:DD:EE:FF") != NULL, "has MAC address");
    
    /* NULL MAC */
    err = ewsp_cmd_build_wake(NULL, json, sizeof(json));
    TEST_ASSERT(err != EWSP_OK, "NULL MAC should fail");
    
    return 1;
}

static int test_cmd_build_info(void) {
    printf("  Testing ewsp_cmd_build_info...\n");
    
    char json[256];
    ewsp_error_t err;
    
    err = ewsp_cmd_build_info(json, sizeof(json));
    TEST_ASSERT_OK(err);
    TEST_ASSERT(strstr(json, "\"cmd\"") != NULL, "has cmd field");
    TEST_ASSERT(strstr(json, "\"info\"") != NULL, "has info value");
    
    return 1;
}

static int test_cmd_build_restart(void) {
    printf("  Testing ewsp_cmd_build_restart...\n");
    
    char json[256];
    ewsp_error_t err;
    
    err = ewsp_cmd_build_restart(json, sizeof(json));
    TEST_ASSERT_OK(err);
    TEST_ASSERT(strstr(json, "\"cmd\"") != NULL, "has cmd field");
    TEST_ASSERT(strstr(json, "\"restart\"") != NULL, "has restart value");
    
    return 1;
}

static int test_cmd_build_generic(void) {
    printf("  Testing ewsp_cmd_build (generic)...\n");
    
    char json[512];
    ewsp_error_t err;
    
    /* Simple command without data */
    err = ewsp_cmd_build("test_cmd", NULL, NULL, json, sizeof(json));
    TEST_ASSERT_OK(err);
    TEST_ASSERT(strstr(json, "\"test_cmd\"") != NULL, "has command name");
    
    /* Command with data */
    err = ewsp_cmd_build("test_cmd", "{\"key\":\"value\"}", NULL, json, sizeof(json));
    TEST_ASSERT_OK(err);
    TEST_ASSERT(strstr(json, "\"test_cmd\"") != NULL, "has command name");
    TEST_ASSERT(strstr(json, "\"key\"") != NULL, "has data key");
    
    return 1;
}

/* ============================================================================
 * Response Building Tests
 * ============================================================================ */

static int test_response_build_ok(void) {
    printf("  Testing ewsp_response_build_ok...\n");
    
    char json[256];
    ewsp_error_t err;
    
    err = ewsp_response_build_ok("req123", json, sizeof(json));
    TEST_ASSERT_OK(err);
    TEST_ASSERT(strstr(json, "\"status\"") != NULL, "has status field");
    TEST_ASSERT(strstr(json, "\"ok\"") != NULL, "has ok status");
    TEST_ASSERT(strstr(json, "\"rid\"") != NULL, "has rid field");
    TEST_ASSERT(strstr(json, "req123") != NULL, "has rid value");
    
    return 1;
}

static int test_response_build_pong(void) {
    printf("  Testing ewsp_response_build_pong...\n");
    
    char json[256];
    ewsp_error_t err;
    
    err = ewsp_response_build_pong("ping123", json, sizeof(json));
    TEST_ASSERT_OK(err);
    TEST_ASSERT(strstr(json, "\"pong\"") != NULL, "has pong response");
    TEST_ASSERT(strstr(json, "ping123") != NULL, "has rid");
    
    return 1;
}

static int test_response_build_error(void) {
    printf("  Testing ewsp_response_build_error...\n");
    
    char json[512];
    ewsp_error_t err;
    
    err = ewsp_response_build_error(EWSP_ERR_AUTH_FAILED, NULL, "req456", json, sizeof(json));
    TEST_ASSERT_OK(err);
    TEST_ASSERT(strstr(json, "\"status\"") != NULL, "has status field");
    TEST_ASSERT(strstr(json, "\"error\"") != NULL, "has error status");
    TEST_ASSERT(strstr(json, "req456") != NULL, "has rid");
    TEST_ASSERT(strstr(json, "AUTH_FAILED") != NULL || 
                strstr(json, "-200") != NULL, "has error code");
    
    return 1;
}

static int test_response_build_info(void) {
    printf("  Testing ewsp_response_build_info...\n");
    
    char json[1024];
    ewsp_error_t err;
    ewsp_device_info_t info;
    
    ewsp_device_info_init(&info);
    strcpy(info.device_id, "test_device");
    strcpy(info.firmware_version, "1.0.0");
    strcpy(info.protocol_version, "1.0");
    strcpy(info.ip_address, "192.168.1.1");
    info.uptime_seconds = 3600;
    
    err = ewsp_response_build_info(&info, "info_req", json, sizeof(json));
    TEST_ASSERT_OK(err);
    TEST_ASSERT(strstr(json, "test_device") != NULL, "has device_id");
    TEST_ASSERT(strstr(json, "1.0.0") != NULL, "has firmware_version");
    TEST_ASSERT(strstr(json, "192.168.1.1") != NULL, "has ip_address");
    
    /* NULL info */
    err = ewsp_response_build_info(NULL, "req", json, sizeof(json));
    TEST_ASSERT(err != EWSP_OK, "NULL info should fail");
    
    return 1;
}

/* ============================================================================
 * Response Parsing Tests
 * ============================================================================ */

static int test_response_parse(void) {
    printf("  Testing ewsp_response_parse...\n");
    
    ewsp_response_t response;
    ewsp_error_t err;
    
    /* Parse OK response */
    const char* ok_json = "{\"status\":\"ok\",\"rid\":\"test123\"}";
    err = ewsp_response_parse(ok_json, &response);
    TEST_ASSERT_OK(err);
    TEST_ASSERT(response.success, "parsed status ok");
    TEST_ASSERT_STR_EQ(response.request_id, "test123", "parsed rid");
    
    /* Parse error response */
    const char* err_json = "{\"status\":\"error\",\"rid\":\"err456\",\"error_code\":-200}";
    err = ewsp_response_parse(err_json, &response);
    TEST_ASSERT_OK(err);
    TEST_ASSERT(!response.success, "parsed error status");
    
    /* NULL inputs */
    err = ewsp_response_parse(NULL, &response);
    TEST_ASSERT(err != EWSP_OK, "NULL json should fail");
    
    err = ewsp_response_parse("{}", NULL);
    TEST_ASSERT(err != EWSP_OK, "NULL response should fail");
    
    return 1;
}

static int test_response_parse_info(void) {
    printf("  Testing ewsp_response_parse_info...\n");
    
    ewsp_device_info_t info;
    ewsp_error_t err;
    
    const char* info_json = "{"
        "\"device_id\":\"wakelink01\","
        "\"firmware_version\":\"1.0.0\","
        "\"protocol_version\":\"1.0\","
        "\"ip\":\"10.0.0.5\","
        "\"mac\":\"AA:BB:CC:DD:EE:FF\","
        "\"uptime\":7200,"
        "\"rssi\":-55,"
        "\"free_heap\":45000"
    "}";
    
    err = ewsp_response_parse_info(info_json, &info);
    TEST_ASSERT_OK(err);
    TEST_ASSERT_STR_EQ(info.device_id, "wakelink01", "parsed device_id");
    TEST_ASSERT_EQ(info.uptime_seconds, 7200, "parsed uptime");
    
    return 1;
}

/* ============================================================================
 * MAC Address Utility Tests
 * ============================================================================ */

static int test_mac_validate(void) {
    printf("  Testing ewsp_mac_validate...\n");
    
    /* Valid MACs */
    TEST_ASSERT(ewsp_mac_validate("AA:BB:CC:DD:EE:FF"), "uppercase colon");
    TEST_ASSERT(ewsp_mac_validate("aa:bb:cc:dd:ee:ff"), "lowercase colon");
    TEST_ASSERT(ewsp_mac_validate("AA-BB-CC-DD-EE-FF"), "uppercase dash");
    TEST_ASSERT(ewsp_mac_validate("aa-bb-cc-dd-ee-ff"), "lowercase dash");
    
    /* Invalid MACs */
    TEST_ASSERT(!ewsp_mac_validate("AA:BB:CC:DD:EE"), "too short");
    TEST_ASSERT(!ewsp_mac_validate("AA:BB:CC:DD:EE:FF:00"), "too long");
    TEST_ASSERT(!ewsp_mac_validate("GG:BB:CC:DD:EE:FF"), "invalid hex");
    TEST_ASSERT(!ewsp_mac_validate("AA:BB:CC:DD:EE:F"), "incomplete");
    TEST_ASSERT(!ewsp_mac_validate(""), "empty");
    TEST_ASSERT(!ewsp_mac_validate(NULL), "NULL");
    
    return 1;
}

static int test_mac_normalize(void) {
    printf("  Testing ewsp_mac_normalize...\n");
    
    char normalized[18];
    ewsp_error_t err;
    
    /* Normalize various formats */
    err = ewsp_mac_normalize("aa:bb:cc:dd:ee:ff", normalized);
    TEST_ASSERT_OK(err);
    TEST_ASSERT_STR_EQ(normalized, "AA:BB:CC:DD:EE:FF", "lowercase to uppercase");
    
    err = ewsp_mac_normalize("AA-BB-CC-DD-EE-FF", normalized);
    TEST_ASSERT_OK(err);
    TEST_ASSERT_STR_EQ(normalized, "AA:BB:CC:DD:EE:FF", "dash to colon");
    
    /* Invalid input */
    err = ewsp_mac_normalize("invalid", normalized);
    TEST_ASSERT(err != EWSP_OK, "invalid MAC should fail");
    
    err = ewsp_mac_normalize(NULL, normalized);
    TEST_ASSERT(err != EWSP_OK, "NULL MAC should fail");
    
    err = ewsp_mac_normalize("AA:BB:CC:DD:EE:FF", NULL);
    TEST_ASSERT(err != EWSP_OK, "NULL output should fail");
    
    return 1;
}

static int test_mac_to_bytes(void) {
    printf("  Testing ewsp_mac_to_bytes...\n");
    
    uint8_t bytes[6];
    ewsp_error_t err;
    
    err = ewsp_mac_to_bytes("AA:BB:CC:DD:EE:FF", bytes);
    TEST_ASSERT_OK(err);
    TEST_ASSERT_EQ(bytes[0], 0xAA, "byte 0");
    TEST_ASSERT_EQ(bytes[1], 0xBB, "byte 1");
    TEST_ASSERT_EQ(bytes[2], 0xCC, "byte 2");
    TEST_ASSERT_EQ(bytes[3], 0xDD, "byte 3");
    TEST_ASSERT_EQ(bytes[4], 0xEE, "byte 4");
    TEST_ASSERT_EQ(bytes[5], 0xFF, "byte 5");
    
    /* Lowercase */
    err = ewsp_mac_to_bytes("11:22:33:44:55:66", bytes);
    TEST_ASSERT_OK(err);
    TEST_ASSERT_EQ(bytes[0], 0x11, "hex 11");
    TEST_ASSERT_EQ(bytes[5], 0x66, "hex 66");
    
    /* Invalid MAC */
    err = ewsp_mac_to_bytes("invalid", bytes);
    TEST_ASSERT(err != EWSP_OK, "invalid should fail");
    
    return 1;
}

/* ============================================================================
 * Test Runner
 * ============================================================================ */

int run_commands_tests(void) {
    printf("\n=== EWSP Commands Tests ===\n\n");
    
    tests_run = 0;
    tests_passed = 0;
    
    int all_passed = 1;
    
    /* Command type tests */
    if (!test_cmd_from_name()) all_passed = 0;
    if (!test_cmd_requires_data()) all_passed = 0;
    
    /* Command building tests */
    if (!test_cmd_build_ping()) all_passed = 0;
    if (!test_cmd_build_wake()) all_passed = 0;
    if (!test_cmd_build_info()) all_passed = 0;
    if (!test_cmd_build_restart()) all_passed = 0;
    if (!test_cmd_build_generic()) all_passed = 0;
    
    /* Response building tests */
    if (!test_response_build_ok()) all_passed = 0;
    if (!test_response_build_pong()) all_passed = 0;
    if (!test_response_build_error()) all_passed = 0;
    if (!test_response_build_info()) all_passed = 0;
    
    /* Response parsing tests */
    if (!test_response_parse()) all_passed = 0;
    if (!test_response_parse_info()) all_passed = 0;
    
    /* MAC utility tests */
    if (!test_mac_validate()) all_passed = 0;
    if (!test_mac_normalize()) all_passed = 0;
    if (!test_mac_to_bytes()) all_passed = 0;
    
    printf("\n--- Commands Tests Summary ---\n");
    printf("Tests run: %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_run - tests_passed);
    printf("Result: %s\n\n", all_passed ? "PASS" : "FAIL");
    
    return all_passed ? 0 : 1;
}
