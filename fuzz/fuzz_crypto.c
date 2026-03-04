/**
 * @file fuzz_crypto.c
 * @brief AFL++ fuzzing harness for ewsp_crypto module
 * 
 * Compile:
 *   afl-gcc -o fuzz_crypto fuzz_crypto.c -I../include -L../build -lewsp_core
 * 
 * Run:
 *   mkdir -p fuzz_input fuzz_output
 *   echo -n "test" > fuzz_input/seed
 *   afl-fuzz -i fuzz_input -o fuzz_output ./fuzz_crypto
 * 
 * @author deadboizxc
 * @version 1.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "ewsp_crypto.h"
#include "ewsp_errors.h"

#ifdef __AFL_HAVE_MANUAL_CONTROL
    #include <unistd.h>
    __AFL_FUZZ_INIT();
#endif

#define MAX_INPUT_SIZE 4096

/* Test key (32 bytes) */
static const uint8_t TEST_KEY[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};

/* Test nonce (24 bytes for XChaCha20) */
static const uint8_t TEST_NONCE[24] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18
};

/**
 * Fuzz SHA256 hashing
 */
static void fuzz_sha256(const uint8_t* data, size_t len) {
    uint8_t hash[32];
    ewsp_sha256(data, len, hash);
}

/**
 * Fuzz HMAC-SHA256
 */
static void fuzz_hmac(const uint8_t* data, size_t len) {
    uint8_t mac[32];
    ewsp_hmac_sha256(TEST_KEY, 32, data, len, mac);
}

/**
 * Fuzz HMAC verification
 */
static void fuzz_hmac_verify(const uint8_t* data, size_t len) {
    if (len < 32) return;
    
    const uint8_t* msg = data + 32;
    size_t msg_len = len - 32;
    
    /* First 32 bytes as "provided" MAC, rest as message */
    ewsp_hmac_sha256_verify(TEST_KEY, 32, msg, msg_len, data);
}

/**
 * Fuzz HKDF key derivation
 */
static void fuzz_hkdf(const uint8_t* data, size_t len) {
    if (len < 16) return;
    
    uint8_t output[64];
    const uint8_t* salt = data;
    size_t salt_len = len / 2;
    const uint8_t* info = data + salt_len;
    size_t info_len = len - salt_len;
    
    ewsp_hkdf_sha256(TEST_KEY, 32, salt, salt_len, info, info_len, output, 64);
}

/**
 * Fuzz XChaCha20-Poly1305 encryption
 */
static void fuzz_encrypt(const uint8_t* data, size_t len) {
    if (len == 0) return;
    
    /* Output buffer: ciphertext + 16-byte tag */
    uint8_t* output = malloc(len + 16);
    if (!output) return;
    
    ewsp_xchacha20_poly1305_encrypt(
        TEST_KEY, 32,
        TEST_NONCE, 24,
        data, len,
        NULL, 0,  /* No AAD */
        output
    );
    
    free(output);
}

/**
 * Fuzz XChaCha20-Poly1305 decryption
 */
static void fuzz_decrypt(const uint8_t* data, size_t len) {
    if (len < 17) return;  /* Need at least 1 byte + 16-byte tag */
    
    size_t plaintext_len = len - 16;
    uint8_t* output = malloc(plaintext_len);
    if (!output) return;
    
    /* Will likely fail (invalid ciphertext), but tests error handling */
    ewsp_xchacha20_poly1305_decrypt(
        TEST_KEY, 32,
        TEST_NONCE, 24,
        data, len,
        NULL, 0,  /* No AAD */
        output
    );
    
    free(output);
}

/**
 * Fuzz hex encoding
 */
static void fuzz_hex_encode(const uint8_t* data, size_t len) {
    char* hex = malloc(len * 2 + 1);
    if (!hex) return;
    
    ewsp_bytes_to_hex(data, len, hex);
    
    free(hex);
}

/**
 * Fuzz hex decoding
 */
static void fuzz_hex_decode(const uint8_t* data, size_t len) {
    /* Treat input as hex string */
    char* hex_str = malloc(len + 1);
    if (!hex_str) return;
    
    memcpy(hex_str, data, len);
    hex_str[len] = '\0';
    
    uint8_t* output = malloc(len / 2 + 1);
    if (output) {
        ewsp_hex_to_bytes(hex_str, output, len / 2 + 1);
        free(output);
    }
    
    free(hex_str);
}

int main(int argc, char* argv[]) {
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
    
    uint8_t* buf = __AFL_FUZZ_TESTCASE_BUF;
    
    while (__AFL_LOOP(10000)) {
        size_t len = __AFL_FUZZ_TESTCASE_LEN;
        if (len > MAX_INPUT_SIZE) len = MAX_INPUT_SIZE;
        if (len == 0) continue;
        
        /* Run all fuzz targets */
        fuzz_sha256(buf, len);
        fuzz_hmac(buf, len);
        fuzz_hmac_verify(buf, len);
        fuzz_hkdf(buf, len);
        fuzz_encrypt(buf, len);
        fuzz_decrypt(buf, len);
        fuzz_hex_encode(buf, len);
        fuzz_hex_decode(buf, len);
    }
#else
    /* Non-AFL mode: read from stdin */
    uint8_t buf[MAX_INPUT_SIZE];
    size_t len = fread(buf, 1, MAX_INPUT_SIZE, stdin);
    
    if (len > 0) {
        fuzz_sha256(buf, len);
        fuzz_hmac(buf, len);
        fuzz_hmac_verify(buf, len);
        fuzz_hkdf(buf, len);
        fuzz_encrypt(buf, len);
        fuzz_decrypt(buf, len);
        fuzz_hex_encode(buf, len);
        fuzz_hex_decode(buf, len);
    }
#endif

    return 0;
}
