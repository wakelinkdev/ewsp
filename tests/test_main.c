/**
 * @file test_main.c
 * @brief EWSP Core Library - Test Runner
 */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

/* Test declarations */
extern int test_crypto_all(void);
extern int test_packet_all(void);
extern int test_json_all(void);
extern int test_chain_all(void);
extern int run_session_tests(void);
extern int run_commands_tests(void);
extern int run_errors_tests(void);
extern int run_models_tests(void);

/* Test framework macros */
#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s\n", msg); \
        return 1; \
    } \
} while(0)

#define TEST_PASS(name) printf("  PASS: %s\n", name)

#define RUN_TEST(name, func) do { \
    printf("Running %s...\n", name); \
    int result = func(); \
    if (result != 0) { \
        printf("%s FAILED\n\n", name); \
        failures++; \
    } else { \
        printf("%s PASSED\n\n", name); \
        passes++; \
    } \
} while(0)

int main(int argc, char* argv[]) {
    int passes = 0;
    int failures = 0;
    bool run_crypto = true;
    bool run_packet = true;
    bool run_json = true;
    bool run_chain = true;
    bool run_session = true;
    bool run_commands = true;
    bool run_errors = true;
    bool run_models = true;
    
    /* Parse arguments */
    if (argc > 1) {
        run_crypto = false;
        run_packet = false;
        run_json = false;
        run_chain = false;
        run_session = false;
        run_commands = false;
        run_errors = false;
        run_models = false;
        
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "crypto") == 0) run_crypto = true;
            else if (strcmp(argv[i], "packet") == 0) run_packet = true;
            else if (strcmp(argv[i], "json") == 0) run_json = true;
            else if (strcmp(argv[i], "chain") == 0) run_chain = true;
            else if (strcmp(argv[i], "session") == 0) run_session = true;
            else if (strcmp(argv[i], "commands") == 0) run_commands = true;
            else if (strcmp(argv[i], "errors") == 0) run_errors = true;
            else if (strcmp(argv[i], "models") == 0) run_models = true;
            else if (strcmp(argv[i], "all") == 0) {
                run_crypto = true;
                run_packet = true;
                run_json = true;
                run_chain = true;
                run_session = true;
                run_commands = true;
                run_errors = true;
                run_models = true;
            }
        }
    }
    
    printf("========================================\n");
    printf("EWSP Core Library Tests\n");
    printf("========================================\n\n");
    
    if (run_crypto) {
        RUN_TEST("Crypto Tests", test_crypto_all);
    }
    
    if (run_json) {
        RUN_TEST("JSON Tests", test_json_all);
    }
    
    if (run_chain) {
        RUN_TEST("Chain Tests", test_chain_all);
    }
    
    if (run_packet) {
        RUN_TEST("Packet Tests", test_packet_all);
    }
    
    if (run_session) {
        RUN_TEST("Session Tests", run_session_tests);
    }
    
    if (run_commands) {
        RUN_TEST("Commands Tests", run_commands_tests);
    }
    
    if (run_errors) {
        RUN_TEST("Errors Tests", run_errors_tests);
    }
    
    if (run_models) {
        RUN_TEST("Models Tests", run_models_tests);
    }
    
    printf("========================================\n");
    printf("Results: %d passed, %d failed\n", passes, failures);
    printf("========================================\n");
    
    return failures > 0 ? 1 : 0;
}
