/**
 * @file fuzz_json.c
 * @brief AFL++ fuzzing harness for ewsp_json module
 * 
 * JSON parsing is a high-risk area for security vulnerabilities.
 * This harness tests:
 * - Malformed JSON handling
 * - Deep nesting
 * - Large values
 * - Unicode handling
 * - Integer overflow
 * 
 * Compile:
 *   afl-gcc -o fuzz_json fuzz_json.c -I../include -L../build -lewsp_core
 * 
 * Run:
 *   mkdir -p fuzz_input/json fuzz_output/json
 *   echo '{"test":1}' > fuzz_input/json/seed1
 *   echo '{"cmd":"ping","rid":"x"}' > fuzz_input/json/seed2
 *   afl-fuzz -i fuzz_input/json -o fuzz_output/json ./fuzz_json
 * 
 * @author deadboizxc
 * @version 1.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "ewsp_json.h"
#include "ewsp_errors.h"

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_FUZZ_INIT();
#endif

#define MAX_INPUT_SIZE 8192

/**
 * Fuzz basic JSON parsing
 */
static void fuzz_parse(const char* json, size_t len) {
    ewsp_json_t doc;
    ewsp_error_t err = ewsp_json_parse(json, &doc);
    
    if (err == EWSP_OK) {
        /* If parsed successfully, try to access values */
        const char* str_val;
        int64_t int_val;
        double float_val;
        bool bool_val;
        
        ewsp_json_get_string(&doc, "cmd", &str_val);
        ewsp_json_get_string(&doc, "rid", &str_val);
        ewsp_json_get_string(&doc, "status", &str_val);
        ewsp_json_get_int(&doc, "seq", &int_val);
        ewsp_json_get_int(&doc, "timestamp", &int_val);
        ewsp_json_get_float(&doc, "value", &float_val);
        ewsp_json_get_bool(&doc, "enabled", &bool_val);
        
        /* Try nested access */
        ewsp_json_t nested;
        if (ewsp_json_get_object(&doc, "data", &nested) == EWSP_OK) {
            ewsp_json_get_string(&nested, "mac", &str_val);
            ewsp_json_get_int(&nested, "port", &int_val);
        }
        
        /* Cleanup */
        ewsp_json_free(&doc);
    }
}

/**
 * Fuzz command JSON parsing
 */
static void fuzz_command_parse(const char* json, size_t len) {
    ewsp_json_t doc;
    char cmd[64] = {0};
    char rid[64] = {0};
    
    ewsp_error_t err = ewsp_json_parse(json, &doc);
    if (err == EWSP_OK) {
        const char* cmd_val;
        const char* rid_val;
        
        if (ewsp_json_get_string(&doc, "cmd", &cmd_val) == EWSP_OK) {
            strncpy(cmd, cmd_val, sizeof(cmd) - 1);
        }
        
        if (ewsp_json_get_string(&doc, "rid", &rid_val) == EWSP_OK) {
            strncpy(rid, rid_val, sizeof(rid) - 1);
        }
        
        ewsp_json_free(&doc);
    }
}

/**
 * Fuzz response JSON parsing
 */
static void fuzz_response_parse(const char* json, size_t len) {
    ewsp_json_t doc;
    
    ewsp_error_t err = ewsp_json_parse(json, &doc);
    if (err == EWSP_OK) {
        const char* status;
        const char* rid;
        int64_t error_code;
        
        ewsp_json_get_string(&doc, "status", &status);
        ewsp_json_get_string(&doc, "rid", &rid);
        ewsp_json_get_int(&doc, "error_code", &error_code);
        
        ewsp_json_free(&doc);
    }
}

/**
 * Fuzz packet JSON (outer protocol packet)
 */
static void fuzz_packet_parse(const char* json, size_t len) {
    ewsp_json_t doc;
    
    ewsp_error_t err = ewsp_json_parse(json, &doc);
    if (err == EWSP_OK) {
        const char* version;
        const char* device_id;
        const char* payload;
        const char* prev_hash;
        const char* signature;
        int64_t seq;
        
        ewsp_json_get_string(&doc, "v", &version);
        ewsp_json_get_string(&doc, "id", &device_id);
        ewsp_json_get_int(&doc, "seq", &seq);
        ewsp_json_get_string(&doc, "prev", &prev_hash);
        ewsp_json_get_string(&doc, "p", &payload);
        ewsp_json_get_string(&doc, "sig", &signature);
        
        ewsp_json_free(&doc);
    }
}

/**
 * Fuzz JSON building
 */
static void fuzz_build(const char* data, size_t len) {
    /* Use fuzzer input as string values */
    char buffer[2048];
    char* safe_str = malloc(len + 1);
    if (!safe_str) return;
    
    memcpy(safe_str, data, len);
    safe_str[len] = '\0';
    
    /* Try building JSON with fuzzed values */
    ewsp_json_builder_t builder;
    ewsp_json_builder_init(&builder, buffer, sizeof(buffer));
    
    ewsp_json_builder_begin_object(&builder);
    ewsp_json_builder_add_string(&builder, "cmd", safe_str);
    ewsp_json_builder_add_string(&builder, "rid", "test123");
    ewsp_json_builder_add_int(&builder, "seq", 42);
    ewsp_json_builder_end_object(&builder);
    
    ewsp_json_builder_finish(&builder);
    
    free(safe_str);
}

/**
 * Fuzz array parsing
 */
static void fuzz_array_parse(const char* json, size_t len) {
    ewsp_json_t doc;
    
    ewsp_error_t err = ewsp_json_parse(json, &doc);
    if (err == EWSP_OK) {
        ewsp_json_t arr;
        if (ewsp_json_get_array(&doc, "items", &arr) == EWSP_OK) {
            size_t arr_len = ewsp_json_array_length(&arr);
            
            /* Iterate array (limit to prevent DoS) */
            for (size_t i = 0; i < arr_len && i < 100; i++) {
                ewsp_json_t item;
                if (ewsp_json_array_get(&arr, i, &item) == EWSP_OK) {
                    const char* val;
                    ewsp_json_get_string(&item, "value", &val);
                }
            }
        }
        
        ewsp_json_free(&doc);
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
        
        /* Null-terminate for JSON parsing */
        char* json = malloc(len + 1);
        if (!json) continue;
        memcpy(json, buf, len);
        json[len] = '\0';
        
        /* Run fuzz targets */
        fuzz_parse(json, len);
        fuzz_command_parse(json, len);
        fuzz_response_parse(json, len);
        fuzz_packet_parse(json, len);
        fuzz_build(json, len);
        fuzz_array_parse(json, len);
        
        free(json);
    }
#else
    /* Non-AFL mode */
    char buf[MAX_INPUT_SIZE];
    size_t len = fread(buf, 1, MAX_INPUT_SIZE - 1, stdin);
    buf[len] = '\0';
    
    if (len > 0) {
        fuzz_parse(buf, len);
        fuzz_command_parse(buf, len);
        fuzz_response_parse(buf, len);
        fuzz_packet_parse(buf, len);
        fuzz_build(buf, len);
        fuzz_array_parse(buf, len);
    }
#endif

    return 0;
}
