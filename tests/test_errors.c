/**
 * @file test_errors.c
 * @brief Unit tests for ewsp_errors module
 * 
 * Tests error code utilities and error info functions.
 * 
 * @version 1.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ewsp_errors.h"

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
#define TEST_ASSERT_NE(a, b, msg) TEST_ASSERT((a) != (b), msg)
#define TEST_ASSERT_NOT_NULL(ptr, msg) TEST_ASSERT((ptr) != NULL, msg)

/* ============================================================================
 * Error Code String Tests
 * ============================================================================ */

static int test_error_code_str(void) {
    printf("  Testing ewsp_error_code_str...\n");
    
    const char* str;
    
    str = ewsp_error_code_str(EWSP_OK);
    TEST_ASSERT_NOT_NULL(str, "OK string");
    TEST_ASSERT(strstr(str, "OK") != NULL, "OK contains 'OK'");
    
    str = ewsp_error_code_str(EWSP_ERR_TIMEOUT);
    TEST_ASSERT_NOT_NULL(str, "TIMEOUT string");
    TEST_ASSERT(strstr(str, "TIMEOUT") != NULL, "TIMEOUT contains 'TIMEOUT'");
    
    str = ewsp_error_code_str(EWSP_ERR_AUTH_FAILED);
    TEST_ASSERT_NOT_NULL(str, "AUTH_FAILED string");
    TEST_ASSERT(strstr(str, "AUTH") != NULL, "AUTH_FAILED contains 'AUTH'");
    
    str = ewsp_error_code_str(EWSP_ERR_INVALID_SIGNATURE);
    TEST_ASSERT_NOT_NULL(str, "INVALID_SIGNATURE string");
    
    str = ewsp_error_code_str(EWSP_ERR_CHAIN_BROKEN);
    TEST_ASSERT_NOT_NULL(str, "CHAIN_BROKEN string");
    TEST_ASSERT(strstr(str, "CHAIN") != NULL, "CHAIN_BROKEN contains 'CHAIN'");
    
    str = ewsp_error_code_str(EWSP_ERR_DECRYPT_FAILED);
    TEST_ASSERT_NOT_NULL(str, "DECRYPT_FAILED string");
    
    str = ewsp_error_code_str(EWSP_ERR_JSON_PARSE);
    TEST_ASSERT_NOT_NULL(str, "JSON_PARSE string");
    
    /* Unknown error code */
    str = ewsp_error_code_str(-9999);
    TEST_ASSERT_NOT_NULL(str, "unknown error has string");
    
    return 1;
}

static int test_error_message(void) {
    printf("  Testing ewsp_error_message...\n");
    
    const char* msg;
    
    msg = ewsp_error_message(EWSP_OK);
    TEST_ASSERT_NOT_NULL(msg, "OK message");
    TEST_ASSERT(strlen(msg) > 0, "OK message not empty");
    
    msg = ewsp_error_message(EWSP_ERR_TIMEOUT);
    TEST_ASSERT_NOT_NULL(msg, "TIMEOUT message");
    TEST_ASSERT(strlen(msg) > 5, "TIMEOUT message descriptive");
    
    msg = ewsp_error_message(EWSP_ERR_AUTH_FAILED);
    TEST_ASSERT_NOT_NULL(msg, "AUTH_FAILED message");
    
    msg = ewsp_error_message(EWSP_ERR_REPLAY_DETECTED);
    TEST_ASSERT_NOT_NULL(msg, "REPLAY_DETECTED message");
    TEST_ASSERT(strstr(msg, "eplay") != NULL || strstr(msg, "REPLAY") != NULL, 
                "REPLAY message mentions replay");
    
    msg = ewsp_error_message(EWSP_ERR_CHAIN_BROKEN);
    TEST_ASSERT_NOT_NULL(msg, "CHAIN_BROKEN message");
    
    /* Unknown error */
    msg = ewsp_error_message(-9999);
    TEST_ASSERT_NOT_NULL(msg, "unknown error has message");
    
    return 1;
}

/* ============================================================================
 * Error Conversion Tests
 * ============================================================================ */

static int test_error_from_str(void) {
    printf("  Testing ewsp_error_from_str...\n");
    
    ewsp_error_t err;
    
    err = ewsp_error_from_str("OK");
    TEST_ASSERT_EQ(err, EWSP_OK, "OK from string");
    
    err = ewsp_error_from_str("TIMEOUT");
    TEST_ASSERT_EQ(err, EWSP_ERR_TIMEOUT, "TIMEOUT from string");
    
    err = ewsp_error_from_str("AUTH_FAILED");
    TEST_ASSERT_EQ(err, EWSP_ERR_AUTH_FAILED, "AUTH_FAILED from string");
    
    err = ewsp_error_from_str("INVALID_SIGNATURE");
    TEST_ASSERT_EQ(err, EWSP_ERR_INVALID_SIGNATURE, "INVALID_SIGNATURE from string");
    
    err = ewsp_error_from_str("CHAIN_BROKEN");
    TEST_ASSERT_EQ(err, EWSP_ERR_CHAIN_BROKEN, "CHAIN_BROKEN from string");
    
    err = ewsp_error_from_str("DECRYPT_FAILED");
    TEST_ASSERT_EQ(err, EWSP_ERR_DECRYPT_FAILED, "DECRYPT_FAILED from string");
    
    /* Unknown string */
    err = ewsp_error_from_str("NOT_A_REAL_ERROR");
    TEST_ASSERT_NE(err, EWSP_OK, "unknown string not OK");
    
    /* NULL */
    err = ewsp_error_from_str(NULL);
    TEST_ASSERT_NE(err, EWSP_OK, "NULL not OK");
    
    /* Empty string */
    err = ewsp_error_from_str("");
    TEST_ASSERT_NE(err, EWSP_OK, "empty not OK");
    
    return 1;
}

/* ============================================================================
 * Error Info Tests
 * ============================================================================ */

static int test_error_get_info(void) {
    printf("  Testing ewsp_error_get_info...\n");
    
    ewsp_error_info_t info;
    
    /* OK status */
    ewsp_error_get_info(EWSP_OK, &info);
    TEST_ASSERT_EQ(info.code, EWSP_OK, "info code is OK");
    TEST_ASSERT_NOT_NULL(info.code_str, "info has code_str");
    TEST_ASSERT_NOT_NULL(info.message, "info has message");
    TEST_ASSERT(!info.is_fatal, "OK not fatal");
    
    /* Connection error */
    ewsp_error_get_info(EWSP_ERR_TIMEOUT, &info);
    TEST_ASSERT_EQ(info.code, EWSP_ERR_TIMEOUT, "info code is TIMEOUT");
    TEST_ASSERT(info.is_retryable, "TIMEOUT is retryable");
    
    /* Auth error */
    ewsp_error_get_info(EWSP_ERR_AUTH_FAILED, &info);
    TEST_ASSERT_EQ(info.code, EWSP_ERR_AUTH_FAILED, "info code is AUTH_FAILED");
    TEST_ASSERT(info.is_fatal, "AUTH_FAILED is fatal");
    
    /* Chain error */
    ewsp_error_get_info(EWSP_ERR_CHAIN_BROKEN, &info);
    TEST_ASSERT_EQ(info.code, EWSP_ERR_CHAIN_BROKEN, "info code is CHAIN_BROKEN");
    TEST_ASSERT(info.needs_chain_reset, "CHAIN_BROKEN needs reset");
    
    return 1;
}

static int test_error_is_retryable(void) {
    printf("  Testing ewsp_error_is_retryable...\n");
    
    /* Retryable errors */
    TEST_ASSERT(ewsp_error_is_retryable(EWSP_ERR_TIMEOUT), "TIMEOUT retryable");
    TEST_ASSERT(ewsp_error_is_retryable(EWSP_ERR_CONNECTION_ERROR), "CONNECTION_ERROR retryable");
    TEST_ASSERT(ewsp_error_is_retryable(EWSP_ERR_NO_RESPONSE), "NO_RESPONSE retryable");
    
    /* Non-retryable errors */
    TEST_ASSERT(!ewsp_error_is_retryable(EWSP_ERR_AUTH_FAILED), "AUTH_FAILED not retryable");
    TEST_ASSERT(!ewsp_error_is_retryable(EWSP_ERR_INVALID_TOKEN), "INVALID_TOKEN not retryable");
    TEST_ASSERT(!ewsp_error_is_retryable(EWSP_ERR_INVALID_SIGNATURE), "INVALID_SIGNATURE not retryable");
    
    /* Success */
    TEST_ASSERT(!ewsp_error_is_retryable(EWSP_OK), "OK not retryable");
    
    return 1;
}

static int test_error_is_fatal(void) {
    printf("  Testing ewsp_error_is_fatal...\n");
    
    /* Fatal errors */
    TEST_ASSERT(ewsp_error_is_fatal(EWSP_ERR_AUTH_FAILED), "AUTH_FAILED fatal");
    TEST_ASSERT(ewsp_error_is_fatal(EWSP_ERR_INVALID_TOKEN), "INVALID_TOKEN fatal");
    
    /* Non-fatal errors */
    TEST_ASSERT(!ewsp_error_is_fatal(EWSP_ERR_TIMEOUT), "TIMEOUT not fatal");
    TEST_ASSERT(!ewsp_error_is_fatal(EWSP_ERR_CONNECTION_ERROR), "CONNECTION_ERROR not fatal");
    TEST_ASSERT(!ewsp_error_is_fatal(EWSP_OK), "OK not fatal");
    
    return 1;
}

static int test_error_needs_chain_reset(void) {
    printf("  Testing ewsp_error_needs_chain_reset...\n");
    
    /* Chain errors needing reset */
    TEST_ASSERT(ewsp_error_needs_chain_reset(EWSP_ERR_CHAIN_BROKEN), "CHAIN_BROKEN needs reset");
    TEST_ASSERT(ewsp_error_needs_chain_reset(EWSP_ERR_CHAIN_DESYNC), "CHAIN_DESYNC needs reset");
    TEST_ASSERT(ewsp_error_needs_chain_reset(EWSP_ERR_CHAIN_RESET_REQUIRED), "CHAIN_RESET_REQUIRED needs reset");
    
    /* Other errors don't need reset */
    TEST_ASSERT(!ewsp_error_needs_chain_reset(EWSP_ERR_AUTH_FAILED), "AUTH_FAILED no reset");
    TEST_ASSERT(!ewsp_error_needs_chain_reset(EWSP_ERR_TIMEOUT), "TIMEOUT no reset");
    TEST_ASSERT(!ewsp_error_needs_chain_reset(EWSP_OK), "OK no reset");
    
    return 1;
}

static int test_error_set_detail(void) {
    printf("  Testing ewsp_error_set_detail...\n");
    
    ewsp_error_info_t info;
    
    ewsp_error_get_info(EWSP_ERR_TIMEOUT, &info);
    
    /* Set detail */
    ewsp_error_set_detail(&info, "Connection to 192.168.1.1 timed out");
    TEST_ASSERT_NOT_NULL(info.detail, "detail set");
    TEST_ASSERT(strstr(info.detail, "192.168.1.1") != NULL, "detail contains IP");
    
    /* Setting empty string clears it */
    ewsp_error_set_detail(&info, "");
    TEST_ASSERT(strlen(info.detail) == 0, "detail cleared");
    
    return 1;
}

/* ============================================================================
 * Error Category Tests  
 * ============================================================================ */

static int test_error_categories(void) {
    printf("  Testing error code categories...\n");
    
    /* Connection errors (100-199) */
    TEST_ASSERT(EWSP_ERR_TIMEOUT <= -100 && EWSP_ERR_TIMEOUT > -200, "TIMEOUT in connection range");
    TEST_ASSERT(EWSP_ERR_CONNECTION_REFUSED <= -100 && EWSP_ERR_CONNECTION_REFUSED > -200, "CONNECTION_REFUSED in range");
    
    /* Auth errors (200-299) */
    TEST_ASSERT(EWSP_ERR_AUTH_FAILED <= -200 && EWSP_ERR_AUTH_FAILED > -300, "AUTH_FAILED in auth range");
    TEST_ASSERT(EWSP_ERR_INVALID_TOKEN <= -200 && EWSP_ERR_INVALID_TOKEN > -300, "INVALID_TOKEN in range");
    
    /* Protocol errors (300-399) */
    TEST_ASSERT(EWSP_ERR_INVALID_SIGNATURE <= -300 && EWSP_ERR_INVALID_SIGNATURE > -400, "INVALID_SIGNATURE in protocol range");
    TEST_ASSERT(EWSP_ERR_REPLAY_DETECTED <= -300 && EWSP_ERR_REPLAY_DETECTED > -400, "REPLAY_DETECTED in range");
    
    /* Chain errors (400-499) */
    TEST_ASSERT(EWSP_ERR_CHAIN_BROKEN <= -400 && EWSP_ERR_CHAIN_BROKEN > -500, "CHAIN_BROKEN in chain range");
    
    /* Crypto errors (500-599) */
    TEST_ASSERT(EWSP_ERR_DECRYPT_FAILED <= -500 && EWSP_ERR_DECRYPT_FAILED > -600, "DECRYPT_FAILED in crypto range");
    
    /* JSON errors (600-699) */
    TEST_ASSERT(EWSP_ERR_JSON_PARSE <= -600 && EWSP_ERR_JSON_PARSE > -700, "JSON_PARSE in json range");
    
    return 1;
}

/* ============================================================================
 * Test Runner
 * ============================================================================ */

int run_errors_tests(void) {
    printf("\n=== EWSP Errors Tests ===\n\n");
    
    tests_run = 0;
    tests_passed = 0;
    
    int all_passed = 1;
    
    /* Error code string tests */
    if (!test_error_code_str()) all_passed = 0;
    if (!test_error_message()) all_passed = 0;
    
    /* Error conversion tests */
    if (!test_error_from_str()) all_passed = 0;
    
    /* Error info tests */
    if (!test_error_get_info()) all_passed = 0;
    if (!test_error_is_retryable()) all_passed = 0;
    if (!test_error_is_fatal()) all_passed = 0;
    if (!test_error_needs_chain_reset()) all_passed = 0;
    if (!test_error_set_detail()) all_passed = 0;
    
    /* Error category tests */
    if (!test_error_categories()) all_passed = 0;
    
    printf("\n--- Errors Tests Summary ---\n");
    printf("Tests run: %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_run - tests_passed);
    printf("Result: %s\n\n", all_passed ? "PASS" : "FAIL");
    
    return all_passed ? 0 : 1;
}
