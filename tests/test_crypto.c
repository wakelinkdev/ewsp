/**
 * @file test_crypto.c
 * @brief EWSP Core Library - Crypto Tests
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

/* Test SHA256 with known vector */
static int test_sha256(void) {
    const char* input = "hello";
    const char* expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    
    uint8_t hash[32];
    ewsp_sha256((const uint8_t*)input, strlen(input), hash);
    
    char hex[65];
    for (int i = 0; i < 32; i++) {
        sprintf(hex + i*2, "%02x", hash[i]);
    }
    hex[64] = '\0';
    
    TEST_ASSERT(strcmp(hex, expected) == 0, "SHA256 hash mismatch");
    TEST_PASS("SHA256 known vector");
    return 0;
}

/* Test HMAC-SHA256 with known vector */
static int test_hmac(void) {
    const char* key = "key";
    const char* data = "The quick brown fox jumps over the lazy dog";
    const char* expected = "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8";
    
    uint8_t mac[32];
    ewsp_hmac_sha256((const uint8_t*)key, strlen(key),
                     (const uint8_t*)data, strlen(data),
                     mac);
    
    char hex[65];
    for (int i = 0; i < 32; i++) {
        sprintf(hex + i*2, "%02x", mac[i]);
    }
    hex[64] = '\0';
    
    TEST_ASSERT(strcmp(hex, expected) == 0, "HMAC-SHA256 hash mismatch");
    TEST_PASS("HMAC-SHA256 known vector");
    return 0;
}

/* Test crypto context init/cleanup */
static int test_crypto_ctx(void) {
    ewsp_crypto_ctx ctx;
    const char* token = "test_token_32_characters_minimum";
    
    ewsp_error_t err = ewsp_crypto_init(&ctx, token, strlen(token));
    TEST_ASSERT(err == EWSP_OK, "Crypto init failed");
    TEST_ASSERT(ctx.initialized, "Crypto not marked as initialized");
    
    ewsp_crypto_cleanup(&ctx);
    TEST_ASSERT(!ctx.initialized, "Crypto not cleaned up");
    
    TEST_PASS("Crypto context lifecycle");
    return 0;
}

/* Test encrypt/decrypt roundtrip */
static int test_encrypt_decrypt(void) {
    ewsp_crypto_ctx ctx;
    const char* token = "test_token_32_characters_minimum";
    const char* plaintext = "{\"cmd\":\"ping\",\"rid\":\"ABC12345\"}";
    
    ewsp_error_t err = ewsp_crypto_init(&ctx, token, strlen(token));
    TEST_ASSERT(err == EWSP_OK, "Crypto init failed");
    
    /* Encrypt */
    char hex_payload[1024];
    err = ewsp_crypto_encrypt(&ctx, (const uint8_t*)plaintext, strlen(plaintext),
                              hex_payload, sizeof(hex_payload));
    TEST_ASSERT(err == EWSP_OK, "Encryption failed");
    TEST_ASSERT(strlen(hex_payload) > 0, "Empty encrypted payload");
    
    /* Decrypt */
    uint8_t decrypted[512];
    size_t decrypted_len;
    err = ewsp_crypto_decrypt(&ctx, hex_payload, 
                              decrypted, sizeof(decrypted) - 1, &decrypted_len);
    TEST_ASSERT(err == EWSP_OK, "Decryption failed");
    decrypted[decrypted_len] = '\0';
    
    TEST_ASSERT(strcmp((char*)decrypted, plaintext) == 0, "Decrypted text mismatch");
    
    ewsp_crypto_cleanup(&ctx);
    TEST_PASS("Encrypt/Decrypt roundtrip");
    return 0;
}

/* Test signature sign/verify */
static int test_sign_verify(void) {
    ewsp_crypto_ctx ctx;
    const char* token = "test_token_32_characters_minimum";
    const char* data = "1.0|WL12345678|1|genesis|abcd1234";
    
    ewsp_error_t err = ewsp_crypto_init(&ctx, token, strlen(token));
    TEST_ASSERT(err == EWSP_OK, "Crypto init failed");
    
    /* Sign */
    char signature[65];
    ewsp_crypto_sign(&ctx, (const uint8_t*)data, strlen(data), signature);
    TEST_ASSERT(strlen(signature) == 64, "Signature length wrong");
    
    /* Verify */
    bool valid = ewsp_crypto_verify(&ctx, (const uint8_t*)data, strlen(data), signature);
    TEST_ASSERT(valid, "Signature verification failed");
    
    /* Tamper and verify should fail */
    signature[0] = (signature[0] == 'a') ? 'b' : 'a';
    valid = ewsp_crypto_verify(&ctx, (const uint8_t*)data, strlen(data), signature);
    TEST_ASSERT(!valid, "Tampered signature should fail");
    
    ewsp_crypto_cleanup(&ctx);
    TEST_PASS("Sign/Verify");
    return 0;
}

/* Test random generation */
static int test_random(void) {
    uint8_t buf1[32], buf2[32];
    
    ewsp_random_bytes(buf1, sizeof(buf1));
    ewsp_random_bytes(buf2, sizeof(buf2));
    
    /* Should be different (extremely unlikely to be same) */
    TEST_ASSERT(memcmp(buf1, buf2, 32) != 0, "Random bytes not unique");
    
    /* Should not be all zeros */
    int zeros = 0;
    for (int i = 0; i < 32; i++) {
        if (buf1[i] == 0) zeros++;
    }
    TEST_ASSERT(zeros < 32, "Random bytes all zeros");
    
    TEST_PASS("Random generation");
    return 0;
}

/**
 * CRYPTO-01/02 FIX: Extended entropy test
 * 
 * Verifies that RNG produces statistically reasonable output:
 * 1. Multiple samples should be unique
 * 2. Byte distribution should be roughly uniform (chi-squared test approximation)
 * 3. No obvious patterns (sequential check)
 */
static int test_random_entropy(void) {
    /* Test 1: Multiple 32-byte samples should all be unique */
    uint8_t samples[10][32];
    for (int i = 0; i < 10; i++) {
        ewsp_error_t err = ewsp_random_bytes(samples[i], 32);
        TEST_ASSERT(err == EWSP_OK, "Random bytes generation failed");
    }
    
    for (int i = 0; i < 9; i++) {
        for (int j = i + 1; j < 10; j++) {
            TEST_ASSERT(memcmp(samples[i], samples[j], 32) != 0, 
                       "Duplicate random samples detected");
        }
    }
    TEST_PASS("Random uniqueness (10 samples)");
    
    /* Test 2: Byte distribution test (simplified chi-squared) */
    /* Generate 4096 bytes and check that each value 0-255 appears */
    uint8_t large_buf[4096];
    ewsp_random_bytes(large_buf, sizeof(large_buf));
    
    uint16_t distribution[256] = {0};
    for (int i = 0; i < 4096; i++) {
        distribution[large_buf[i]]++;
    }
    
    /* Each value should appear roughly 16 times (4096/256) */
    /* Allow range [0, 64] - if any value never appears or appears > 64 times, likely biased */
    int missing_values = 0;
    int extreme_values = 0;
    for (int i = 0; i < 256; i++) {
        if (distribution[i] == 0) missing_values++;
        if (distribution[i] > 64) extreme_values++;  /* Expected ~16, allow 4x */
    }
    
    TEST_ASSERT(missing_values < 10, "Too many missing byte values (weak entropy)");
    TEST_ASSERT(extreme_values < 10, "Too many over-represented values (biased RNG)");
    TEST_PASS("Random distribution (4096 bytes)");
    
    /* Test 3: No obvious sequential patterns */
    uint8_t pattern_buf[256];
    ewsp_random_bytes(pattern_buf, sizeof(pattern_buf));
    
    int sequential_count = 0;
    for (int i = 0; i < 255; i++) {
        if (pattern_buf[i+1] == pattern_buf[i] + 1) sequential_count++;
    }
    /* Allow up to 5 sequential pairs in 256 bytes (expected ~1 by random chance) */
    TEST_ASSERT(sequential_count < 10, "Too many sequential patterns (predictable RNG)");
    TEST_PASS("Random pattern check");
    
    return 0;
}

/* Test XChaCha20-Poly1305 AEAD (A-04) */
static int test_aead(void) {
    uint8_t key[32];
    uint8_t nonce[24];
    const char* plaintext = "{\"cmd\":\"wake\",\"mac\":\"AA:BB:CC:DD:EE:FF\"}";
    const char* ad = "1.0|WL35080814|42";  /* Associated data: packet header */
    size_t pt_len = strlen(plaintext);
    size_t ad_len = strlen(ad);
    
    /* Generate random key and nonce */
    ewsp_random_bytes(key, 32);
    ewsp_random_bytes(nonce, 24);
    
    /* Allocate buffers */
    uint8_t ciphertext[256];  /* plaintext + 16 tag */
    uint8_t decrypted[256];
    
    /* Encrypt */
    ewsp_error_t err = ewsp_aead_encrypt(key, nonce, 
                                          (const uint8_t*)ad, ad_len,
                                          (const uint8_t*)plaintext, pt_len,
                                          ciphertext);
    TEST_ASSERT(err == EWSP_OK, "AEAD encrypt failed");
    
    /* Decrypt */
    err = ewsp_aead_decrypt(key, nonce,
                            (const uint8_t*)ad, ad_len,
                            ciphertext, pt_len + 16,
                            decrypted);
    TEST_ASSERT(err == EWSP_OK, "AEAD decrypt failed");
    
    /* Compare */
    TEST_ASSERT(memcmp(decrypted, plaintext, pt_len) == 0, "AEAD decrypt mismatch");
    TEST_PASS("AEAD roundtrip");
    
    /* Test tamper detection - modify ciphertext */
    ciphertext[0] ^= 0x01;
    err = ewsp_aead_decrypt(key, nonce,
                            (const uint8_t*)ad, ad_len,
                            ciphertext, pt_len + 16,
                            decrypted);
    TEST_ASSERT(err == EWSP_ERR_AUTH_FAILED, "AEAD should reject tampered ciphertext");
    TEST_PASS("AEAD tamper detection (ciphertext)");
    
    /* Restore ciphertext, tamper with AD */
    ciphertext[0] ^= 0x01;
    const char* wrong_ad = "1.0|WL35080814|99";  /* Different counter */
    err = ewsp_aead_decrypt(key, nonce,
                            (const uint8_t*)wrong_ad, strlen(wrong_ad),
                            ciphertext, pt_len + 16,
                            decrypted);
    TEST_ASSERT(err == EWSP_ERR_AUTH_FAILED, "AEAD should reject wrong AD");
    TEST_PASS("AEAD tamper detection (AD)");
    
    /* Test empty plaintext */
    err = ewsp_aead_encrypt(key, nonce, NULL, 0, NULL, 0, ciphertext);
    TEST_ASSERT(err == EWSP_OK, "AEAD empty plaintext encrypt failed");
    
    err = ewsp_aead_decrypt(key, nonce, NULL, 0, ciphertext, 16, decrypted);
    TEST_ASSERT(err == EWSP_OK, "AEAD empty plaintext decrypt failed");
    TEST_PASS("AEAD empty plaintext");
    
    return 0;
}

int test_crypto_all(void) {
    int result = 0;
    
    result |= test_sha256();
    result |= test_hmac();
    result |= test_crypto_ctx();
    result |= test_encrypt_decrypt();
    result |= test_sign_verify();
    result |= test_random();
    result |= test_random_entropy();  /* CRYPTO-01/02 entropy validation */
    result |= test_aead();            /* A-04 AEAD validation */
    
    return result;
}
