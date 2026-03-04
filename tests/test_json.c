/**
 * @file test_json.c
 * @brief EWSP Core Library - JSON Tests
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

/* Test JSON reader - string */
static int test_json_read_string(void) {
    const char* json = "{\"name\":\"device1\",\"status\":\"ok\"}";
    ewsp_json_reader_t r;
    ewsp_json_reader_init(&r, json, strlen(json));
    
    char value[64];
    ewsp_error_t err = ewsp_json_get_string(&r, "name", value, sizeof(value));
    TEST_ASSERT(err == EWSP_OK, "Failed to read 'name'");
    TEST_ASSERT(strcmp(value, "device1") == 0, "Wrong value for 'name'");
    
    err = ewsp_json_get_string(&r, "status", value, sizeof(value));
    TEST_ASSERT(err == EWSP_OK, "Failed to read 'status'");
    TEST_ASSERT(strcmp(value, "ok") == 0, "Wrong value for 'status'");
    
    err = ewsp_json_get_string(&r, "missing", value, sizeof(value));
    TEST_ASSERT(err == EWSP_ERR_MISSING_FIELD, "Should return missing field");
    
    TEST_PASS("JSON read string");
    return 0;
}

/* Test JSON reader - numbers */
static int test_json_read_numbers(void) {
    const char* json = "{\"seq\":42,\"timestamp\":1732924800000,\"rssi\":-65}";
    ewsp_json_reader_t r;
    ewsp_json_reader_init(&r, json, strlen(json));
    
    uint64_t seq;
    ewsp_error_t err = ewsp_json_get_uint(&r, "seq", &seq);
    TEST_ASSERT(err == EWSP_OK, "Failed to read 'seq'");
    TEST_ASSERT(seq == 42, "Wrong value for 'seq'");
    
    uint64_t ts;
    err = ewsp_json_get_uint(&r, "timestamp", &ts);
    TEST_ASSERT(err == EWSP_OK, "Failed to read 'timestamp'");
    TEST_ASSERT(ts == 1732924800000ULL, "Wrong value for 'timestamp'");
    
    int64_t rssi;
    err = ewsp_json_get_int(&r, "rssi", &rssi);
    TEST_ASSERT(err == EWSP_OK, "Failed to read 'rssi'");
    TEST_ASSERT(rssi == -65, "Wrong value for 'rssi'");
    
    TEST_PASS("JSON read numbers");
    return 0;
}

/* Test JSON reader - booleans */
static int test_json_read_bool(void) {
    const char* json = "{\"enabled\":true,\"connected\":false}";
    ewsp_json_reader_t r;
    ewsp_json_reader_init(&r, json, strlen(json));
    
    bool value;
    ewsp_error_t err = ewsp_json_get_bool(&r, "enabled", &value);
    TEST_ASSERT(err == EWSP_OK, "Failed to read 'enabled'");
    TEST_ASSERT(value == true, "Wrong value for 'enabled'");
    
    err = ewsp_json_get_bool(&r, "connected", &value);
    TEST_ASSERT(err == EWSP_OK, "Failed to read 'connected'");
    TEST_ASSERT(value == false, "Wrong value for 'connected'");
    
    TEST_PASS("JSON read booleans");
    return 0;
}

/* Test JSON reader - nested objects */
static int test_json_read_object(void) {
    const char* json = "{\"cmd\":\"wake\",\"d\":{\"mac\":\"AA:BB:CC:DD:EE:FF\"},\"rid\":\"ABC12345\"}";
    ewsp_json_reader_t r;
    ewsp_json_reader_init(&r, json, strlen(json));
    
    char cmd[32];
    ewsp_error_t err = ewsp_json_get_string(&r, "cmd", cmd, sizeof(cmd));
    TEST_ASSERT(err == EWSP_OK, "Failed to read 'cmd'");
    TEST_ASSERT(strcmp(cmd, "wake") == 0, "Wrong value for 'cmd'");
    
    char data_obj[128];
    err = ewsp_json_get_object(&r, "d", data_obj, sizeof(data_obj));
    TEST_ASSERT(err == EWSP_OK, "Failed to read 'd' object");
    TEST_ASSERT(strstr(data_obj, "AA:BB:CC:DD:EE:FF") != NULL, "MAC not in object");
    
    TEST_PASS("JSON read nested object");
    return 0;
}

/* Test JSON writer */
static int test_json_writer(void) {
    char buffer[256];
    ewsp_json_writer_t w;
    ewsp_json_writer_init(&w, buffer, sizeof(buffer));
    
    ewsp_json_write_object_start(&w);
    ewsp_json_write_kv_string(&w, "cmd", "ping");
    ewsp_json_write_kv_int(&w, "seq", 42);
    ewsp_json_write_kv_bool(&w, "ok", true);
    ewsp_json_write_object_end(&w);
    ewsp_json_writer_finish(&w);
    
    TEST_ASSERT(!ewsp_json_writer_has_error(&w), "Writer has error");
    
    /* Verify output can be read back */
    ewsp_json_reader_t r;
    ewsp_json_reader_init(&r, buffer, strlen(buffer));
    
    char cmd[32];
    ewsp_error_t err = ewsp_json_get_string(&r, "cmd", cmd, sizeof(cmd));
    TEST_ASSERT(err == EWSP_OK, "Failed to read back 'cmd'");
    TEST_ASSERT(strcmp(cmd, "ping") == 0, "Wrong value for 'cmd'");
    
    int64_t seq;
    err = ewsp_json_get_int(&r, "seq", &seq);
    TEST_ASSERT(err == EWSP_OK, "Failed to read back 'seq'");
    TEST_ASSERT(seq == 42, "Wrong value for 'seq'");
    
    bool ok;
    err = ewsp_json_get_bool(&r, "ok", &ok);
    TEST_ASSERT(err == EWSP_OK, "Failed to read back 'ok'");
    TEST_ASSERT(ok == true, "Wrong value for 'ok'");
    
    TEST_PASS("JSON writer");
    return 0;
}

/* Test JSON has_key */
static int test_json_has_key(void) {
    const char* json = "{\"name\":\"test\",\"count\":5}";
    ewsp_json_reader_t r;
    ewsp_json_reader_init(&r, json, strlen(json));
    
    TEST_ASSERT(ewsp_json_has_key(&r, "name"), "Should have 'name' key");
    TEST_ASSERT(ewsp_json_has_key(&r, "count"), "Should have 'count' key");
    TEST_ASSERT(!ewsp_json_has_key(&r, "missing"), "Should not have 'missing' key");
    
    TEST_PASS("JSON has_key");
    return 0;
}

/* Test escape/unescape */
static int test_json_escape(void) {
    const char* input = "Hello\nWorld\t\"Test\"";
    char escaped[128];
    
    int len = ewsp_json_escape_string(input, escaped, sizeof(escaped));
    TEST_ASSERT(len > 0, "Escape failed");
    TEST_ASSERT(strstr(escaped, "\\n") != NULL, "Newline not escaped");
    TEST_ASSERT(strstr(escaped, "\\t") != NULL, "Tab not escaped");
    TEST_ASSERT(strstr(escaped, "\\\"") != NULL, "Quote not escaped");
    
    char unescaped[128];
    len = ewsp_json_unescape_string(escaped, strlen(escaped), unescaped, sizeof(unescaped));
    TEST_ASSERT(len > 0, "Unescape failed");
    TEST_ASSERT(strcmp(unescaped, input) == 0, "Roundtrip failed");
    
    TEST_PASS("JSON escape/unescape");
    return 0;
}

int test_json_all(void) {
    int result = 0;
    
    result |= test_json_read_string();
    result |= test_json_read_numbers();
    result |= test_json_read_bool();
    result |= test_json_read_object();
    result |= test_json_writer();
    result |= test_json_has_key();
    result |= test_json_escape();
    
    return result;
}
