/**
 * @file ewsp_crypto.c
 * @brief EWSP Core Library - Cryptographic Primitives Implementation
 * 
 * @author deadboizxc
 * @version 1.0
 */

#include "ewsp_crypto.h"
#include <stdlib.h>

/* ============================================================================
 * SHA-256 Constants
 * ============================================================================ */

static const uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const uint32_t SHA256_H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/* ============================================================================
 * SHA-256 Helper Macros
 * ============================================================================ */

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

/* ============================================================================
 * SHA-256 Implementation
 * ============================================================================ */

static void sha256_transform(ewsp_sha256_ctx* ctx) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2;
    int i;

    /* Prepare message schedule */
    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)ctx->buffer[i * 4] << 24) |
               ((uint32_t)ctx->buffer[i * 4 + 1] << 16) |
               ((uint32_t)ctx->buffer[i * 4 + 2] << 8) |
               ((uint32_t)ctx->buffer[i * 4 + 3]);
    }
    for (i = 16; i < 64; i++) {
        w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];
    }

    /* Initialize working variables */
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    /* Main loop */
    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + SHA256_K[i] + w[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    /* Add to state */
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void ewsp_sha256_init(ewsp_sha256_ctx* ctx) {
    memcpy(ctx->state, SHA256_H0, sizeof(SHA256_H0));
    ctx->bitlen = 0;
    ctx->buflen = 0;
}

void ewsp_sha256_update(ewsp_sha256_ctx* ctx, const uint8_t* data, size_t len) {
    size_t i;

    for (i = 0; i < len; i++) {
        ctx->buffer[ctx->buflen++] = data[i];
        if (ctx->buflen == 64) {
            sha256_transform(ctx);
            ctx->bitlen += 512;
            ctx->buflen = 0;
        }
    }
}

void ewsp_sha256_final(ewsp_sha256_ctx* ctx, uint8_t hash[32]) {
    uint32_t i;
    uint64_t bitlen;

    i = ctx->buflen;

    /* Pad message */
    ctx->buffer[i++] = 0x80;
    if (i > 56) {
        while (i < 64) ctx->buffer[i++] = 0x00;
        sha256_transform(ctx);
        i = 0;
    }
    while (i < 56) ctx->buffer[i++] = 0x00;

    /* Append length */
    bitlen = ctx->bitlen + ctx->buflen * 8;
    ctx->buffer[56] = (uint8_t)(bitlen >> 56);
    ctx->buffer[57] = (uint8_t)(bitlen >> 48);
    ctx->buffer[58] = (uint8_t)(bitlen >> 40);
    ctx->buffer[59] = (uint8_t)(bitlen >> 32);
    ctx->buffer[60] = (uint8_t)(bitlen >> 24);
    ctx->buffer[61] = (uint8_t)(bitlen >> 16);
    ctx->buffer[62] = (uint8_t)(bitlen >> 8);
    ctx->buffer[63] = (uint8_t)(bitlen);
    sha256_transform(ctx);

    /* Output hash (big-endian) */
    for (i = 0; i < 8; i++) {
        hash[i * 4] = (uint8_t)(ctx->state[i] >> 24);
        hash[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        hash[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        hash[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

void ewsp_sha256(const uint8_t* data, size_t len, uint8_t hash[32]) {
    ewsp_sha256_ctx ctx;
    ewsp_sha256_init(&ctx);
    ewsp_sha256_update(&ctx, data, len);
    ewsp_sha256_final(&ctx, hash);
}

void ewsp_sha256_to_hash(const uint8_t* data, size_t len, ewsp_hash_t* hash) {
    ewsp_sha256(data, len, hash->bytes);
}

/* ============================================================================
 * HMAC-SHA256 Implementation
 * ============================================================================ */

void ewsp_hmac_init(ewsp_hmac_ctx* ctx, const uint8_t* key, size_t key_len) {
    uint8_t key_block[64];
    uint8_t ipad[64];
    size_t i;

    memset(key_block, 0, 64);

    /* If key > 64 bytes, hash it */
    if (key_len > 64) {
        ewsp_sha256(key, key_len, key_block);
    } else {
        memcpy(key_block, key, key_len);
    }

    /* Prepare pads */
    for (i = 0; i < 64; i++) {
        ipad[i] = key_block[i] ^ 0x36;
        ctx->key_pad[i] = key_block[i] ^ 0x5c;
    }

    /* Initialize inner hash with ipad */
    ewsp_sha256_init(&ctx->inner);
    ewsp_sha256_update(&ctx->inner, ipad, 64);

    /* Secure cleanup */
    ewsp_secure_zero(key_block, 64);
    ewsp_secure_zero(ipad, 64);
}

void ewsp_hmac_update(ewsp_hmac_ctx* ctx, const uint8_t* data, size_t len) {
    ewsp_sha256_update(&ctx->inner, data, len);
}

void ewsp_hmac_final(ewsp_hmac_ctx* ctx, uint8_t mac[32]) {
    uint8_t inner_hash[32];

    /* Finalize inner hash */
    ewsp_sha256_final(&ctx->inner, inner_hash);

    /* Compute outer hash: H(opad || inner_hash) */
    ewsp_sha256_init(&ctx->outer);
    ewsp_sha256_update(&ctx->outer, ctx->key_pad, 64);
    ewsp_sha256_update(&ctx->outer, inner_hash, 32);
    ewsp_sha256_final(&ctx->outer, mac);

    /* Secure cleanup */
    ewsp_secure_zero(inner_hash, 32);
    ewsp_secure_zero(ctx->key_pad, 64);
}

void ewsp_hmac_sha256(const uint8_t* key, size_t key_len,
                      const uint8_t* data, size_t data_len,
                      uint8_t mac[32]) {
    ewsp_hmac_ctx ctx;
    ewsp_hmac_init(&ctx, key, key_len);
    ewsp_hmac_update(&ctx, data, data_len);
    ewsp_hmac_final(&ctx, mac);
}

int ewsp_hmac_verify(const uint8_t mac1[32], const uint8_t mac2[32]) {
    return ewsp_constant_time_compare(mac1, mac2, 32);
}

/* ============================================================================
 * HKDF-SHA256 Implementation (RFC 5869)
 * ============================================================================ */

void ewsp_hkdf_extract(const uint8_t* salt, size_t salt_len,
                       const uint8_t* ikm, size_t ikm_len,
                       uint8_t prk[32]) {
    uint8_t default_salt[32] = {0};
    
    if (salt == NULL || salt_len == 0) {
        salt = default_salt;
        salt_len = 32;
    }
    
    ewsp_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

void ewsp_hkdf_expand(const uint8_t prk[32],
                      const uint8_t* info, size_t info_len,
                      uint8_t* okm, size_t okm_len) {
    uint8_t t[32];
    uint8_t counter = 1;
    size_t offset = 0;
    size_t t_len = 0;
    ewsp_hmac_ctx ctx;
    
    while (offset < okm_len) {
        ewsp_hmac_init(&ctx, prk, 32);
        
        /* T(n) = HMAC(PRK, T(n-1) || info || counter) */
        if (t_len > 0) {
            ewsp_hmac_update(&ctx, t, t_len);
        }
        if (info_len > 0) {
            ewsp_hmac_update(&ctx, info, info_len);
        }
        ewsp_hmac_update(&ctx, &counter, 1);
        ewsp_hmac_final(&ctx, t);
        
        /* Copy to output */
        size_t copy_len = (okm_len - offset < 32) ? (okm_len - offset) : 32;
        memcpy(okm + offset, t, copy_len);
        
        offset += copy_len;
        t_len = 32;
        counter++;
    }
    
    ewsp_secure_zero(t, 32);
}

void ewsp_hkdf(const uint8_t* salt, size_t salt_len,
               const uint8_t* ikm, size_t ikm_len,
               const uint8_t* info, size_t info_len,
               uint8_t* okm, size_t okm_len) {
    uint8_t prk[32];
    
    ewsp_hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
    ewsp_hkdf_expand(prk, info, info_len, okm, okm_len);
    
    ewsp_secure_zero(prk, 32);
}

/* ============================================================================
 * ChaCha20 Implementation (RFC 7539)
 * ============================================================================ */

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define QUARTERROUND(a, b, c, d) \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d, 8);  \
    c += d; b ^= c; b = ROTL32(b, 7);

static uint32_t load32_le(const uint8_t* p) {
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void store32_le(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

void ewsp_chacha20_block(const uint8_t key[32], const uint8_t nonce[12],
                         uint32_t counter, uint8_t block[64]) {
    uint32_t state[16];
    uint32_t working[16];
    int i;

    /* ChaCha20 constants: "expand 32-byte k" */
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    /* Key (little-endian) */
    for (i = 0; i < 8; i++) {
        state[4 + i] = load32_le(key + i * 4);
    }

    /* Counter */
    state[12] = counter;

    /* Nonce (little-endian) */
    for (i = 0; i < 3; i++) {
        state[13 + i] = load32_le(nonce + i * 4);
    }

    /* Copy state for working */
    memcpy(working, state, sizeof(state));

    /* 20 rounds (10 double-rounds) */
    for (i = 0; i < 10; i++) {
        /* Column rounds */
        QUARTERROUND(working[0], working[4], working[8],  working[12]);
        QUARTERROUND(working[1], working[5], working[9],  working[13]);
        QUARTERROUND(working[2], working[6], working[10], working[14]);
        QUARTERROUND(working[3], working[7], working[11], working[15]);
        /* Diagonal rounds */
        QUARTERROUND(working[0], working[5], working[10], working[15]);
        QUARTERROUND(working[1], working[6], working[11], working[12]);
        QUARTERROUND(working[2], working[7], working[8],  working[13]);
        QUARTERROUND(working[3], working[4], working[9],  working[14]);
    }

    /* Add original state */
    for (i = 0; i < 16; i++) {
        working[i] += state[i];
    }

    /* Output (little-endian) */
    for (i = 0; i < 16; i++) {
        store32_le(block + i * 4, working[i]);
    }
}

void ewsp_chacha20(const uint8_t key[32], const uint8_t nonce[12],
                   uint32_t counter,
                   const uint8_t* input, uint8_t* output, size_t len) {
    uint8_t keystream[64];
    size_t i, j;

    for (i = 0; i < len; i += 64) {
        ewsp_chacha20_block(key, nonce, counter++, keystream);
        
        size_t block_len = (len - i < 64) ? (len - i) : 64;
        for (j = 0; j < block_len; j++) {
            output[i + j] = input[i + j] ^ keystream[j];
        }
    }

    ewsp_secure_zero(keystream, 64);
}

/* ============================================================================
 * XChaCha20 Implementation
 * ============================================================================ */

void ewsp_hchacha20(const uint8_t key[32], const uint8_t nonce[16],
                    uint8_t subkey[32]) {
    uint32_t state[16];
    int i;

    /* ChaCha20 constants */
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    /* Key */
    for (i = 0; i < 8; i++) {
        state[4 + i] = load32_le(key + i * 4);
    }

    /* Nonce (16 bytes for HChaCha20) */
    for (i = 0; i < 4; i++) {
        state[12 + i] = load32_le(nonce + i * 4);
    }

    /* 20 rounds - NO final addition */
    for (i = 0; i < 10; i++) {
        QUARTERROUND(state[0], state[4], state[8],  state[12]);
        QUARTERROUND(state[1], state[5], state[9],  state[13]);
        QUARTERROUND(state[2], state[6], state[10], state[14]);
        QUARTERROUND(state[3], state[7], state[11], state[15]);
        QUARTERROUND(state[0], state[5], state[10], state[15]);
        QUARTERROUND(state[1], state[6], state[11], state[12]);
        QUARTERROUND(state[2], state[7], state[8],  state[13]);
        QUARTERROUND(state[3], state[4], state[9],  state[14]);
    }

    /* Extract subkey: words 0-3 and 12-15 */
    for (i = 0; i < 4; i++) {
        store32_le(subkey + i * 4, state[i]);
    }
    for (i = 0; i < 4; i++) {
        store32_le(subkey + 16 + i * 4, state[12 + i]);
    }
}

void ewsp_xchacha20(const uint8_t key[32], const uint8_t nonce[24],
                    uint32_t counter,
                    const uint8_t* input, uint8_t* output, size_t len) {
    uint8_t subkey[32];
    uint8_t chacha_nonce[12];

    /* Step 1: Derive subkey using HChaCha20 with first 16 bytes of nonce */
    ewsp_hchacha20(key, nonce, subkey);

    /* Step 2: Create ChaCha20 nonce: 0x00000000 || nonce[16:24] */
    memset(chacha_nonce, 0, 4);
    memcpy(chacha_nonce + 4, nonce + 16, 8);

    /* Step 3: Use ChaCha20 with subkey and modified nonce */
    ewsp_chacha20(subkey, chacha_nonce, counter, input, output, len);

    ewsp_secure_zero(subkey, 32);
}

/* ============================================================================
 * Poly1305 MAC Implementation (RFC 7539)
 * ============================================================================ */

/**
 * Poly1305 operates on 130-bit integers using 5 32-bit limbs.
 * The prime is 2^130 - 5.
 */

static void poly1305_clamp(uint32_t r[5], const uint8_t key[16]) {
    /* Load r from first 16 bytes with clamping */
    r[0] = load32_le(key) & 0x0fffffff;
    r[1] = load32_le(key + 3) >> 2 & 0x0ffffffc;
    r[2] = load32_le(key + 6) >> 4 & 0x0ffffffc;
    r[3] = load32_le(key + 9) >> 6 & 0x0ffffffc;
    r[4] = load32_le(key + 12) >> 8 & 0x0ffffffc;
}

void ewsp_poly1305_init(ewsp_poly1305_ctx* ctx, const uint8_t key[32]) {
    /* Clamp r (first 16 bytes) */
    poly1305_clamp(ctx->r, key);
    
    /* Initialize accumulator to 0 */
    ctx->h[0] = ctx->h[1] = ctx->h[2] = ctx->h[3] = ctx->h[4] = 0;
    
    /* Load s (last 16 bytes) - NOT clamped */
    ctx->pad[0] = load32_le(key + 16);
    ctx->pad[1] = load32_le(key + 20);
    ctx->pad[2] = load32_le(key + 24);
    ctx->pad[3] = load32_le(key + 28);
    
    ctx->buflen = 0;
    ctx->finalized = false;
}

static void poly1305_block(ewsp_poly1305_ctx* ctx, const uint8_t block[16], uint32_t hibit) {
    uint32_t r0, r1, r2, r3, r4;
    uint32_t s1, s2, s3, s4;
    uint32_t h0, h1, h2, h3, h4;
    uint64_t d0, d1, d2, d3, d4;
    uint32_t c;

    r0 = ctx->r[0];
    r1 = ctx->r[1];
    r2 = ctx->r[2];
    r3 = ctx->r[3];
    r4 = ctx->r[4];

    s1 = r1 * 5;
    s2 = r2 * 5;
    s3 = r3 * 5;
    s4 = r4 * 5;

    h0 = ctx->h[0];
    h1 = ctx->h[1];
    h2 = ctx->h[2];
    h3 = ctx->h[3];
    h4 = ctx->h[4];

    /* h += m[i] */
    h0 += load32_le(block) & 0x03ffffff;
    h1 += (load32_le(block + 3) >> 2) & 0x03ffffff;
    h2 += (load32_le(block + 6) >> 4) & 0x03ffffff;
    h3 += (load32_le(block + 9) >> 6) & 0x03ffffff;
    h4 += (load32_le(block + 12) >> 8) | hibit;

    /* h *= r */
    d0 = ((uint64_t)h0 * r0) + ((uint64_t)h1 * s4) + ((uint64_t)h2 * s3) + 
         ((uint64_t)h3 * s2) + ((uint64_t)h4 * s1);
    d1 = ((uint64_t)h0 * r1) + ((uint64_t)h1 * r0) + ((uint64_t)h2 * s4) + 
         ((uint64_t)h3 * s3) + ((uint64_t)h4 * s2);
    d2 = ((uint64_t)h0 * r2) + ((uint64_t)h1 * r1) + ((uint64_t)h2 * r0) + 
         ((uint64_t)h3 * s4) + ((uint64_t)h4 * s3);
    d3 = ((uint64_t)h0 * r3) + ((uint64_t)h1 * r2) + ((uint64_t)h2 * r1) + 
         ((uint64_t)h3 * r0) + ((uint64_t)h4 * s4);
    d4 = ((uint64_t)h0 * r4) + ((uint64_t)h1 * r3) + ((uint64_t)h2 * r2) + 
         ((uint64_t)h3 * r1) + ((uint64_t)h4 * r0);

    /* Partial reduction mod 2^130-5 */
    c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x03ffffff;
    d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x03ffffff;
    d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x03ffffff;
    d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x03ffffff;
    d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x03ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x03ffffff;
    h1 += c;

    ctx->h[0] = h0;
    ctx->h[1] = h1;
    ctx->h[2] = h2;
    ctx->h[3] = h3;
    ctx->h[4] = h4;
}

void ewsp_poly1305_update(ewsp_poly1305_ctx* ctx, const uint8_t* data, size_t len) {
    size_t i;

    /* Process any buffered data */
    if (ctx->buflen > 0) {
        size_t want = 16 - ctx->buflen;
        if (want > len) want = len;
        memcpy(ctx->buffer + ctx->buflen, data, want);
        ctx->buflen += want;
        data += want;
        len -= want;
        if (ctx->buflen == 16) {
            poly1305_block(ctx, ctx->buffer, 1 << 24);
            ctx->buflen = 0;
        }
    }

    /* Process full blocks */
    while (len >= 16) {
        poly1305_block(ctx, data, 1 << 24);
        data += 16;
        len -= 16;
    }

    /* Buffer remaining */
    if (len > 0) {
        memcpy(ctx->buffer, data, len);
        ctx->buflen = len;
    }
}

void ewsp_poly1305_final(ewsp_poly1305_ctx* ctx, uint8_t tag[16]) {
    uint32_t h0, h1, h2, h3, h4, c;
    uint32_t g0, g1, g2, g3, g4;
    uint64_t f;
    uint32_t mask;

    /* Process remaining bytes */
    if (ctx->buflen > 0) {
        ctx->buffer[ctx->buflen] = 1;
        memset(ctx->buffer + ctx->buflen + 1, 0, 16 - ctx->buflen - 1);
        poly1305_block(ctx, ctx->buffer, 0);
    }

    /* Fully carry h */
    h0 = ctx->h[0]; h1 = ctx->h[1]; h2 = ctx->h[2]; h3 = ctx->h[3]; h4 = ctx->h[4];

    c = h1 >> 26; h1 &= 0x03ffffff;
    h2 += c; c = h2 >> 26; h2 &= 0x03ffffff;
    h3 += c; c = h3 >> 26; h3 &= 0x03ffffff;
    h4 += c; c = h4 >> 26; h4 &= 0x03ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x03ffffff;
    h1 += c;

    /* Compute h + -p (= h - (2^130 - 5)) */
    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x03ffffff;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x03ffffff;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x03ffffff;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x03ffffff;
    g4 = h4 + c - (1 << 26);

    /* Select h if h < p, or h - p if h >= p */
    mask = (g4 >> 31) - 1;  /* All 1s if g4 < 0 (i.e., h < p) */
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* h = h % (2^128) */
    h0 = (h0) | (h1 << 26);
    h1 = (h1 >> 6) | (h2 << 20);
    h2 = (h2 >> 12) | (h3 << 14);
    h3 = (h3 >> 18) | (h4 << 8);

    /* mac = (h + pad) % (2^128) */
    f = (uint64_t)h0 + ctx->pad[0]; h0 = (uint32_t)f;
    f = (uint64_t)h1 + ctx->pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + ctx->pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + ctx->pad[3] + (f >> 32); h3 = (uint32_t)f;

    store32_le(tag, h0);
    store32_le(tag + 4, h1);
    store32_le(tag + 8, h2);
    store32_le(tag + 12, h3);

    /* Secure cleanup */
    ewsp_secure_zero(ctx, sizeof(*ctx));
    ctx->finalized = true;
}

void ewsp_poly1305(const uint8_t key[32], const uint8_t* data, size_t len, uint8_t tag[16]) {
    ewsp_poly1305_ctx ctx;
    ewsp_poly1305_init(&ctx, key);
    ewsp_poly1305_update(&ctx, data, len);
    ewsp_poly1305_final(&ctx, tag);
}

/* ============================================================================
 * XChaCha20-Poly1305 AEAD Implementation (RFC 7539 + XChaCha extension)
 * ============================================================================ */

/**
 * Construct Poly1305 input per RFC 7539 Section 2.8:
 * - Pad AD to 16-byte boundary
 * - Ciphertext padded to 16-byte boundary
 * - 8-byte LE length of AD
 * - 8-byte LE length of ciphertext
 */
static void aead_construct_data(ewsp_poly1305_ctx* poly_ctx,
                                 const uint8_t* ad, size_t ad_len,
                                 const uint8_t* ct, size_t ct_len) {
    uint8_t len_block[16];
    size_t pad_len;
    static const uint8_t zeros[16] = {0};

    /* Process AD */
    if (ad && ad_len > 0) {
        ewsp_poly1305_update(poly_ctx, ad, ad_len);
        pad_len = (16 - (ad_len % 16)) % 16;
        if (pad_len > 0) {
            ewsp_poly1305_update(poly_ctx, zeros, pad_len);
        }
    }

    /* Process ciphertext */
    if (ct && ct_len > 0) {
        ewsp_poly1305_update(poly_ctx, ct, ct_len);
        pad_len = (16 - (ct_len % 16)) % 16;
        if (pad_len > 0) {
            ewsp_poly1305_update(poly_ctx, zeros, pad_len);
        }
    }

    /* Append lengths (little-endian 64-bit) */
    store32_le(len_block, (uint32_t)ad_len);
    store32_le(len_block + 4, (uint32_t)(ad_len >> 32));
    store32_le(len_block + 8, (uint32_t)ct_len);
    store32_le(len_block + 12, (uint32_t)(ct_len >> 32));
    ewsp_poly1305_update(poly_ctx, len_block, 16);
}

ewsp_error_t ewsp_aead_encrypt(const uint8_t key[32],
                                const uint8_t nonce[24],
                                const uint8_t* ad, size_t ad_len,
                                const uint8_t* plaintext, size_t plaintext_len,
                                uint8_t* ciphertext) {
    uint8_t subkey[32];
    uint8_t chacha_nonce[12];
    uint8_t poly_key[32];
    ewsp_poly1305_ctx poly_ctx;

    if (!key || !nonce || !ciphertext) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    if (plaintext_len > 0 && !plaintext) {
        return EWSP_ERR_INVALID_PARAMS;
    }

    /* Step 1: Derive subkey using HChaCha20 */
    ewsp_hchacha20(key, nonce, subkey);

    /* Step 2: Create ChaCha20 nonce for internal use */
    memset(chacha_nonce, 0, 4);
    memcpy(chacha_nonce + 4, nonce + 16, 8);

    /* Step 3: Generate Poly1305 one-time key (counter = 0) */
    memset(poly_key, 0, 32);
    ewsp_chacha20(subkey, chacha_nonce, 0, poly_key, poly_key, 32);

    /* Step 4: Encrypt plaintext (counter = 1) */
    if (plaintext_len > 0) {
        ewsp_chacha20(subkey, chacha_nonce, 1, plaintext, ciphertext, plaintext_len);
    }

    /* Step 5: Compute Poly1305 tag */
    ewsp_poly1305_init(&poly_ctx, poly_key);
    aead_construct_data(&poly_ctx, ad, ad_len, ciphertext, plaintext_len);
    ewsp_poly1305_final(&poly_ctx, ciphertext + plaintext_len);

    /* Cleanup */
    ewsp_secure_zero(subkey, 32);
    ewsp_secure_zero(poly_key, 32);

    return EWSP_OK;
}

ewsp_error_t ewsp_aead_decrypt(const uint8_t key[32],
                                const uint8_t nonce[24],
                                const uint8_t* ad, size_t ad_len,
                                const uint8_t* ciphertext, size_t ciphertext_len,
                                uint8_t* plaintext) {
    uint8_t subkey[32];
    uint8_t chacha_nonce[12];
    uint8_t poly_key[32];
    uint8_t expected_tag[16];
    ewsp_poly1305_ctx poly_ctx;

    if (!key || !nonce || !plaintext) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    if (ciphertext_len < EWSP_AEAD_TAG_SIZE) {
        return EWSP_ERR_INVALID_LENGTH;
    }
    if (ciphertext_len > EWSP_AEAD_TAG_SIZE && !ciphertext) {
        return EWSP_ERR_INVALID_PARAMS;
    }

    size_t ct_len = ciphertext_len - EWSP_AEAD_TAG_SIZE;

    /* Step 1: Derive subkey using HChaCha20 */
    ewsp_hchacha20(key, nonce, subkey);

    /* Step 2: Create ChaCha20 nonce */
    memset(chacha_nonce, 0, 4);
    memcpy(chacha_nonce + 4, nonce + 16, 8);

    /* Step 3: Generate Poly1305 one-time key */
    memset(poly_key, 0, 32);
    ewsp_chacha20(subkey, chacha_nonce, 0, poly_key, poly_key, 32);

    /* Step 4: Verify tag BEFORE decryption */
    ewsp_poly1305_init(&poly_ctx, poly_key);
    aead_construct_data(&poly_ctx, ad, ad_len, ciphertext, ct_len);
    ewsp_poly1305_final(&poly_ctx, expected_tag);

    /* Constant-time tag comparison */
    if (!ewsp_constant_time_compare(expected_tag, ciphertext + ct_len, 16)) {
        ewsp_secure_zero(subkey, 32);
        ewsp_secure_zero(poly_key, 32);
        ewsp_secure_zero(expected_tag, 16);
        return EWSP_ERR_AUTH_FAILED;
    }

    /* Step 5: Decrypt ciphertext (counter = 1) */
    if (ct_len > 0) {
        ewsp_chacha20(subkey, chacha_nonce, 1, ciphertext, plaintext, ct_len);
    }

    /* Cleanup */
    ewsp_secure_zero(subkey, 32);
    ewsp_secure_zero(poly_key, 32);
    ewsp_secure_zero(expected_tag, 16);

    return EWSP_OK;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

int ewsp_constant_time_compare(const uint8_t* a, const uint8_t* b, size_t len) {
    volatile uint8_t result = 0;
    size_t i;
    
    for (i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    
    return (result == 0) ? 1 : 0;
}

void ewsp_secure_zero(void* ptr, size_t len) {
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    while (len--) {
        *p++ = 0;
    }
}

void ewsp_bytes_to_hex(const uint8_t* data, size_t len, char* hex) {
    static const char hex_chars[] = "0123456789abcdef";
    size_t i;
    
    for (i = 0; i < len; i++) {
        hex[i * 2] = hex_chars[(data[i] >> 4) & 0x0F];
        hex[i * 2 + 1] = hex_chars[data[i] & 0x0F];
    }
    hex[len * 2] = '\0';
}

int ewsp_hex_to_bytes(const char* hex, uint8_t* data, size_t len) {
    size_t i;
    
    for (i = 0; i < len; i++) {
        uint8_t high, low;
        char c;
        
        c = hex[i * 2];
        if (c >= '0' && c <= '9') high = c - '0';
        else if (c >= 'a' && c <= 'f') high = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') high = c - 'A' + 10;
        else return -1;
        
        c = hex[i * 2 + 1];
        if (c >= '0' && c <= '9') low = c - '0';
        else if (c >= 'a' && c <= 'f') low = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') low = c - 'A' + 10;
        else return -1;
        
        data[i] = (high << 4) | low;
    }
    
    return 0;
}

/* Platform-specific random bytes */
#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#include <wincrypt.h>

ewsp_error_t ewsp_random_bytes(uint8_t* buffer, size_t len) {
    HCRYPTPROV hProvider = 0;
    
    if (!CryptAcquireContextW(&hProvider, NULL, NULL, PROV_RSA_FULL, 
                              CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        return EWSP_ERR_INTERNAL;
    }
    
    if (!CryptGenRandom(hProvider, (DWORD)len, buffer)) {
        CryptReleaseContext(hProvider, 0);
        return EWSP_ERR_INTERNAL;
    }
    
    CryptReleaseContext(hProvider, 0);
    return EWSP_OK;
}

#elif defined(__APPLE__) || defined(__linux__) || defined(__unix__)
#include <fcntl.h>
#include <unistd.h>

ewsp_error_t ewsp_random_bytes(uint8_t* buffer, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return EWSP_ERR_INTERNAL;
    }
    
    ssize_t bytes_read = read(fd, buffer, len);
    close(fd);
    
    if (bytes_read != (ssize_t)len) {
        return EWSP_ERR_INTERNAL;
    }
    
    return EWSP_OK;
}

#elif defined(ESP_PLATFORM) || defined(ARDUINO)
/* ESP32/ESP8266 - use hardware RNG */
extern uint32_t esp_random(void);

ewsp_error_t ewsp_random_bytes(uint8_t* buffer, size_t len) {
    size_t i;
    for (i = 0; i < len; i += 4) {
        uint32_t r = esp_random();
        size_t copy_len = (len - i < 4) ? (len - i) : 4;
        memcpy(buffer + i, &r, copy_len);
    }
    return EWSP_OK;
}

#else
/* No fallback - require secure RNG */
#error "No cryptographically secure random number generator available! Define one of: _WIN32, __linux__, ESP_PLATFORM, ARDUINO"

ewsp_error_t ewsp_random_bytes(uint8_t* buffer, size_t len) {
    (void)buffer;
    (void)len;
    return EWSP_ERR_CRYPTO_UNAVAILABLE;
}
#endif

/* ============================================================================
 * High-Level Crypto API
 * ============================================================================ */

ewsp_error_t ewsp_crypto_init(ewsp_crypto_ctx* ctx, 
                              const char* token, 
                              size_t token_len) {
    if (!ctx || !token) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    if (token_len < EWSP_MIN_TOKEN_LEN) {
        return EWSP_ERR_TOKEN_TOO_SHORT;
    }
    
    /* Derive master key: SHA256(token) */
    uint8_t master_key[32];
    ewsp_sha256((const uint8_t*)token, token_len, master_key);
    
    /* CRYPTO-03 FIX: Key separation using HKDF */
    /* Derive encryption key */
    ewsp_hkdf(NULL, 0, master_key, 32, 
              (const uint8_t*)"wakelink_encryption_v2", 22,
              ctx->chacha_key.bytes, 32);
    
    /* Derive authentication key */
    ewsp_hkdf(NULL, 0, master_key, 32,
              (const uint8_t*)"wakelink_authentication_v2", 26,
              ctx->hmac_key.bytes, 32);
    
    ewsp_secure_zero(master_key, 32);
    
    ctx->initialized = true;
    return EWSP_OK;
}

void ewsp_crypto_cleanup(ewsp_crypto_ctx* ctx) {
    if (ctx) {
        ewsp_secure_zero(&ctx->chacha_key, sizeof(ctx->chacha_key));
        ewsp_secure_zero(&ctx->hmac_key, sizeof(ctx->hmac_key));
        ctx->initialized = false;
    }
}

ewsp_error_t ewsp_crypto_encrypt(const ewsp_crypto_ctx* ctx,
                                  const uint8_t* plaintext,
                                  size_t plaintext_len,
                                  char* hex_out,
                                  size_t hex_out_size) {
    if (!ctx || !ctx->initialized) {
        return EWSP_ERR_INVALID_KEY;
    }
    
    if (!plaintext || !hex_out) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    /* Check output buffer size:
     * Format: [2B length] + [ciphertext] + [24B nonce]
     * Hex doubles the size, plus null terminator
     */
    size_t binary_len = 2 + plaintext_len + EWSP_NONCE_SIZE;
    size_t required_hex_size = binary_len * 2 + 1;
    
    if (hex_out_size < required_hex_size) {
        return EWSP_ERR_BUFFER_TOO_SMALL;
    }
    
    /* Allocate binary buffer */
    uint8_t* binary = (uint8_t*)malloc(binary_len);
    if (!binary) {
        return EWSP_ERR_OUT_OF_MEMORY;
    }
    
    /* Generate random nonce */
    uint8_t nonce[EWSP_NONCE_SIZE];
    ewsp_error_t err = ewsp_random_bytes(nonce, EWSP_NONCE_SIZE);
    if (err != EWSP_OK) {
        free(binary);
        return err;
    }
    
    /* Write length (big-endian) */
    binary[0] = (uint8_t)(plaintext_len >> 8);
    binary[1] = (uint8_t)(plaintext_len);
    
    /* Encrypt with XChaCha20 */
    ewsp_xchacha20(ctx->chacha_key.bytes, nonce, 1, 
                   plaintext, binary + 2, plaintext_len);
    
    /* Append nonce */
    memcpy(binary + 2 + plaintext_len, nonce, EWSP_NONCE_SIZE);
    
    /* Convert to hex */
    ewsp_bytes_to_hex(binary, binary_len, hex_out);
    
    ewsp_secure_zero(binary, binary_len);
    free(binary);
    
    return EWSP_OK;
}

ewsp_error_t ewsp_crypto_decrypt(const ewsp_crypto_ctx* ctx,
                                  const char* hex_payload,
                                  uint8_t* plaintext_out,
                                  size_t plaintext_size,
                                  size_t* plaintext_len_out) {
    if (!ctx || !ctx->initialized) {
        return EWSP_ERR_INVALID_KEY;
    }
    
    if (!hex_payload || !plaintext_out || !plaintext_len_out) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    size_t hex_len = strlen(hex_payload);
    if (hex_len % 2 != 0) {
        return EWSP_ERR_BAD_PACKET;
    }
    
    size_t binary_len = hex_len / 2;
    
    /* Minimum: 2 (length) + 0 (ciphertext) + 24 (nonce) = 26 bytes */
    if (binary_len < 2 + EWSP_NONCE_SIZE) {
        return EWSP_ERR_BAD_PACKET;
    }
    
    /* Allocate binary buffer */
    uint8_t* binary = (uint8_t*)malloc(binary_len);
    if (!binary) {
        return EWSP_ERR_OUT_OF_MEMORY;
    }
    
    /* Decode hex */
    if (ewsp_hex_to_bytes(hex_payload, binary, binary_len) != 0) {
        free(binary);
        return EWSP_ERR_BAD_PACKET;
    }
    
    /* Extract length (big-endian) */
    size_t plaintext_len = ((size_t)binary[0] << 8) | binary[1];
    
    /* Validate length */
    if (2 + plaintext_len + EWSP_NONCE_SIZE != binary_len) {
        free(binary);
        return EWSP_ERR_INVALID_LENGTH;
    }
    
    if (plaintext_len > plaintext_size) {
        free(binary);
        return EWSP_ERR_BUFFER_TOO_SMALL;
    }
    
    /* Extract nonce (last 24 bytes) */
    uint8_t nonce[EWSP_NONCE_SIZE];
    memcpy(nonce, binary + 2 + plaintext_len, EWSP_NONCE_SIZE);
    
    /* Decrypt with XChaCha20 */
    ewsp_xchacha20(ctx->chacha_key.bytes, nonce, 1,
                   binary + 2, plaintext_out, plaintext_len);
    
    *plaintext_len_out = plaintext_len;
    
    ewsp_secure_zero(binary, binary_len);
    free(binary);
    
    return EWSP_OK;
}

void ewsp_crypto_sign(const ewsp_crypto_ctx* ctx,
                      const uint8_t* data,
                      size_t data_len,
                      char sig_hex_out[65]) {
    uint8_t mac[32];
    ewsp_hmac_sha256(ctx->hmac_key.bytes, 32, data, data_len, mac);
    ewsp_bytes_to_hex(mac, 32, sig_hex_out);
    ewsp_secure_zero(mac, 32);
}

bool ewsp_crypto_verify(const ewsp_crypto_ctx* ctx,
                        const uint8_t* data,
                        size_t data_len,
                        const char* sig_hex) {
    if (!ctx || !ctx->initialized || !data || !sig_hex) {
        return false;
    }
    
    if (strlen(sig_hex) != 64) {
        return false;
    }
    
    /* Calculate expected HMAC */
    uint8_t expected[32];
    ewsp_hmac_sha256(ctx->hmac_key.bytes, 32, data, data_len, expected);
    
    /* Decode provided signature */
    uint8_t provided[32];
    if (ewsp_hex_to_bytes(sig_hex, provided, 32) != 0) {
        return false;
    }
    
    /* Constant-time compare */
    bool result = ewsp_hmac_verify(expected, provided) == 1;
    
    ewsp_secure_zero(expected, 32);
    ewsp_secure_zero(provided, 32);
    
    return result;
}
