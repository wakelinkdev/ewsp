/**
 * @file ewsp_core_jni.c
 * @brief EWSP Core JNI Binding for Kotlin/Android
 * 
 * JNI wrapper functions that bridge Kotlin code to ewsp-core C library.
 * 
 * Build with Android NDK or desktop JNI.
 * 
 * @version 1.0
 * @author deadboizxc
 */

#include <jni.h>
#include <stdlib.h>
#include <string.h>

/* Include ewsp-core headers */
#include "ewsp.h"
#include "ewsp_crypto.h"
#include "ewsp_errors.h"

/* JNI class name for CryptoNative */
#define JNI_CLASS "org/wakelink/ewsp/CryptoNative"

/* ============================================================================
 * Helper Macros
 * ============================================================================ */

#define GET_BYTE_ARRAY(env, arr, ptr, len) \
    jbyte* ptr = (*env)->GetByteArrayElements(env, arr, NULL); \
    jsize len = (*env)->GetArrayLength(env, arr)

#define RELEASE_BYTE_ARRAY(env, arr, ptr) \
    (*env)->ReleaseByteArrayElements(env, arr, ptr, JNI_ABORT)

#define CREATE_BYTE_ARRAY(env, data, len) \
    jbyteArray result = (*env)->NewByteArray(env, len); \
    if (result != NULL) { \
        (*env)->SetByteArrayRegion(env, result, 0, len, (jbyte*)data); \
    }

/* ============================================================================
 * Version Functions
 * ============================================================================ */

/**
 * Get library version string.
 * 
 * Kotlin: external fun version(): String
 */
JNIEXPORT jstring JNICALL
Java_org_wakelink_ewsp_CryptoNative_version(JNIEnv *env, jobject thiz) {
    (void)thiz;
    const char* version = ewsp_version();
    return (*env)->NewStringUTF(env, version);
}

/**
 * Get protocol version string.
 * 
 * Kotlin: external fun protocolVersion(): String
 */
JNIEXPORT jstring JNICALL
Java_org_wakelink_ewsp_CryptoNative_protocolVersion(JNIEnv *env, jobject thiz) {
    (void)thiz;
    const char* version = ewsp_protocol_version();
    return (*env)->NewStringUTF(env, version);
}

/* ============================================================================
 * SHA-256
 * ============================================================================ */

/**
 * Compute SHA-256 hash.
 * 
 * Kotlin: external fun sha256(data: ByteArray): ByteArray
 */
JNIEXPORT jbyteArray JNICALL
Java_org_wakelink_ewsp_CryptoNative_sha256(JNIEnv *env, jobject thiz, jbyteArray data) {
    (void)thiz;
    
    GET_BYTE_ARRAY(env, data, data_ptr, data_len);
    if (data_ptr == NULL) return NULL;
    
    uint8_t hash[32];
    ewsp_sha256((const uint8_t*)data_ptr, data_len, hash);
    
    RELEASE_BYTE_ARRAY(env, data, data_ptr);
    
    CREATE_BYTE_ARRAY(env, hash, 32);
    return result;
}

/* ============================================================================
 * HMAC-SHA256
 * ============================================================================ */

/**
 * Compute HMAC-SHA256.
 * 
 * Kotlin: external fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray
 */
JNIEXPORT jbyteArray JNICALL
Java_org_wakelink_ewsp_CryptoNative_hmacSha256(JNIEnv *env, jobject thiz, 
                                               jbyteArray key, jbyteArray data) {
    (void)thiz;
    
    GET_BYTE_ARRAY(env, key, key_ptr, key_len);
    GET_BYTE_ARRAY(env, data, data_ptr, data_len);
    
    if (key_ptr == NULL || data_ptr == NULL) {
        if (key_ptr) RELEASE_BYTE_ARRAY(env, key, key_ptr);
        if (data_ptr) RELEASE_BYTE_ARRAY(env, data, data_ptr);
        return NULL;
    }
    
    uint8_t mac[32];
    ewsp_hmac_sha256((const uint8_t*)key_ptr, key_len,
                     (const uint8_t*)data_ptr, data_len, mac);
    
    RELEASE_BYTE_ARRAY(env, key, key_ptr);
    RELEASE_BYTE_ARRAY(env, data, data_ptr);
    
    CREATE_BYTE_ARRAY(env, mac, 32);
    return result;
}

/**
 * Constant-time HMAC verification.
 * 
 * Kotlin: external fun hmacVerify(mac1: ByteArray, mac2: ByteArray): Boolean
 */
JNIEXPORT jboolean JNICALL
Java_org_wakelink_ewsp_CryptoNative_hmacVerify(JNIEnv *env, jobject thiz,
                                                jbyteArray mac1, jbyteArray mac2) {
    (void)thiz;
    
    jsize len1 = (*env)->GetArrayLength(env, mac1);
    jsize len2 = (*env)->GetArrayLength(env, mac2);
    
    if (len1 != 32 || len2 != 32) return JNI_FALSE;
    
    GET_BYTE_ARRAY(env, mac1, mac1_ptr, mac1_len);
    GET_BYTE_ARRAY(env, mac2, mac2_ptr, mac2_len);
    (void)mac1_len; (void)mac2_len;
    
    if (mac1_ptr == NULL || mac2_ptr == NULL) {
        if (mac1_ptr) RELEASE_BYTE_ARRAY(env, mac1, mac1_ptr);
        if (mac2_ptr) RELEASE_BYTE_ARRAY(env, mac2, mac2_ptr);
        return JNI_FALSE;
    }
    
    int result = ewsp_hmac_verify((const uint8_t*)mac1_ptr, (const uint8_t*)mac2_ptr);
    
    RELEASE_BYTE_ARRAY(env, mac1, mac1_ptr);
    RELEASE_BYTE_ARRAY(env, mac2, mac2_ptr);
    
    return result ? JNI_TRUE : JNI_FALSE;
}

/* ============================================================================
 * HKDF-SHA256
 * ============================================================================ */

/**
 * HKDF-SHA256 key derivation.
 * 
 * Kotlin: external fun hkdf(salt: ByteArray?, ikm: ByteArray, info: ByteArray, length: Int): ByteArray
 */
JNIEXPORT jbyteArray JNICALL
Java_org_wakelink_ewsp_CryptoNative_hkdf(JNIEnv *env, jobject thiz,
                                          jbyteArray salt, jbyteArray ikm,
                                          jbyteArray info, jint length) {
    (void)thiz;
    
    const uint8_t* salt_ptr = NULL;
    jsize salt_len = 0;
    jbyte* salt_jbyte = NULL;
    
    if (salt != NULL) {
        salt_jbyte = (*env)->GetByteArrayElements(env, salt, NULL);
        salt_ptr = (const uint8_t*)salt_jbyte;
        salt_len = (*env)->GetArrayLength(env, salt);
    }
    
    GET_BYTE_ARRAY(env, ikm, ikm_ptr, ikm_len);
    GET_BYTE_ARRAY(env, info, info_ptr, info_len);
    
    if (ikm_ptr == NULL || info_ptr == NULL) {
        if (salt_jbyte) (*env)->ReleaseByteArrayElements(env, salt, salt_jbyte, JNI_ABORT);
        if (ikm_ptr) RELEASE_BYTE_ARRAY(env, ikm, ikm_ptr);
        if (info_ptr) RELEASE_BYTE_ARRAY(env, info, info_ptr);
        return NULL;
    }
    
    uint8_t* okm = (uint8_t*)malloc(length);
    if (okm == NULL) {
        if (salt_jbyte) (*env)->ReleaseByteArrayElements(env, salt, salt_jbyte, JNI_ABORT);
        RELEASE_BYTE_ARRAY(env, ikm, ikm_ptr);
        RELEASE_BYTE_ARRAY(env, info, info_ptr);
        return NULL;
    }
    
    ewsp_hkdf(salt_ptr, salt_len,
              (const uint8_t*)ikm_ptr, ikm_len,
              (const uint8_t*)info_ptr, info_len,
              okm, length);
    
    if (salt_jbyte) (*env)->ReleaseByteArrayElements(env, salt, salt_jbyte, JNI_ABORT);
    RELEASE_BYTE_ARRAY(env, ikm, ikm_ptr);
    RELEASE_BYTE_ARRAY(env, info, info_ptr);
    
    CREATE_BYTE_ARRAY(env, okm, length);
    free(okm);
    return result;
}

/* ============================================================================
 * XChaCha20
 * ============================================================================ */

/**
 * XChaCha20 encryption/decryption.
 * 
 * Kotlin: external fun xchacha20(key: ByteArray, nonce: ByteArray, data: ByteArray): ByteArray
 */
JNIEXPORT jbyteArray JNICALL
Java_org_wakelink_ewsp_CryptoNative_xchacha20(JNIEnv *env, jobject thiz,
                                               jbyteArray key, jbyteArray nonce,
                                               jbyteArray data) {
    (void)thiz;
    
    jsize key_len = (*env)->GetArrayLength(env, key);
    jsize nonce_len = (*env)->GetArrayLength(env, nonce);
    
    if (key_len != 32 || nonce_len < 24) {
        return NULL;  // Invalid parameters
    }
    
    GET_BYTE_ARRAY(env, key, key_ptr, key_len2);
    GET_BYTE_ARRAY(env, nonce, nonce_ptr, nonce_len2);
    GET_BYTE_ARRAY(env, data, data_ptr, data_len);
    (void)key_len2; (void)nonce_len2;
    
    if (key_ptr == NULL || nonce_ptr == NULL || data_ptr == NULL) {
        if (key_ptr) RELEASE_BYTE_ARRAY(env, key, key_ptr);
        if (nonce_ptr) RELEASE_BYTE_ARRAY(env, nonce, nonce_ptr);
        if (data_ptr) RELEASE_BYTE_ARRAY(env, data, data_ptr);
        return NULL;
    }
    
    uint8_t* output = (uint8_t*)malloc(data_len);
    if (output == NULL) {
        RELEASE_BYTE_ARRAY(env, key, key_ptr);
        RELEASE_BYTE_ARRAY(env, nonce, nonce_ptr);
        RELEASE_BYTE_ARRAY(env, data, data_ptr);
        return NULL;
    }
    
    ewsp_xchacha20((const uint8_t*)key_ptr, (const uint8_t*)nonce_ptr, 0,
                   (const uint8_t*)data_ptr, output, data_len);
    
    RELEASE_BYTE_ARRAY(env, key, key_ptr);
    RELEASE_BYTE_ARRAY(env, nonce, nonce_ptr);
    RELEASE_BYTE_ARRAY(env, data, data_ptr);
    
    CREATE_BYTE_ARRAY(env, output, data_len);
    free(output);
    return result;
}

/* ============================================================================
 * Poly1305
 * ============================================================================ */

/**
 * Poly1305 MAC.
 * 
 * Kotlin: external fun poly1305(key: ByteArray, data: ByteArray): ByteArray
 */
JNIEXPORT jbyteArray JNICALL
Java_org_wakelink_ewsp_CryptoNative_poly1305(JNIEnv *env, jobject thiz,
                                              jbyteArray key, jbyteArray data) {
    (void)thiz;
    
    jsize key_len = (*env)->GetArrayLength(env, key);
    if (key_len != 32) return NULL;
    
    GET_BYTE_ARRAY(env, key, key_ptr, key_len2);
    GET_BYTE_ARRAY(env, data, data_ptr, data_len);
    (void)key_len2;
    
    if (key_ptr == NULL || data_ptr == NULL) {
        if (key_ptr) RELEASE_BYTE_ARRAY(env, key, key_ptr);
        if (data_ptr) RELEASE_BYTE_ARRAY(env, data, data_ptr);
        return NULL;
    }
    
    uint8_t tag[16];
    ewsp_poly1305((const uint8_t*)key_ptr, (const uint8_t*)data_ptr, data_len, tag);
    
    RELEASE_BYTE_ARRAY(env, key, key_ptr);
    RELEASE_BYTE_ARRAY(env, data, data_ptr);
    
    CREATE_BYTE_ARRAY(env, tag, 16);
    return result;
}

/* ============================================================================
 * XChaCha20-Poly1305 AEAD
 * ============================================================================ */

/**
 * XChaCha20-Poly1305 authenticated encryption.
 * 
 * Returns ciphertext with 16-byte tag appended.
 * 
 * Kotlin: external fun aeadEncrypt(key: ByteArray, nonce: ByteArray, 
 *                                   plaintext: ByteArray, ad: ByteArray?): ByteArray
 */
JNIEXPORT jbyteArray JNICALL
Java_org_wakelink_ewsp_CryptoNative_aeadEncrypt(JNIEnv *env, jobject thiz,
                                                 jbyteArray key, jbyteArray nonce,
                                                 jbyteArray plaintext, jbyteArray ad) {
    (void)thiz;
    
    jsize key_len = (*env)->GetArrayLength(env, key);
    jsize nonce_len = (*env)->GetArrayLength(env, nonce);
    
    if (key_len != 32 || nonce_len < 24) return NULL;
    
    GET_BYTE_ARRAY(env, key, key_ptr, key_len2);
    GET_BYTE_ARRAY(env, nonce, nonce_ptr, nonce_len2);
    GET_BYTE_ARRAY(env, plaintext, pt_ptr, pt_len);
    (void)key_len2; (void)nonce_len2;
    
    const uint8_t* ad_ptr = NULL;
    jsize ad_len = 0;
    jbyte* ad_jbyte = NULL;
    
    if (ad != NULL) {
        ad_jbyte = (*env)->GetByteArrayElements(env, ad, NULL);
        ad_ptr = (const uint8_t*)ad_jbyte;
        ad_len = (*env)->GetArrayLength(env, ad);
    }
    
    if (key_ptr == NULL || nonce_ptr == NULL || pt_ptr == NULL) {
        if (key_ptr) RELEASE_BYTE_ARRAY(env, key, key_ptr);
        if (nonce_ptr) RELEASE_BYTE_ARRAY(env, nonce, nonce_ptr);
        if (pt_ptr) RELEASE_BYTE_ARRAY(env, plaintext, pt_ptr);
        if (ad_jbyte) (*env)->ReleaseByteArrayElements(env, ad, ad_jbyte, JNI_ABORT);
        return NULL;
    }
    
    size_t ct_len = pt_len + 16;  // ciphertext + tag
    uint8_t* ciphertext = (uint8_t*)malloc(ct_len);
    if (ciphertext == NULL) {
        RELEASE_BYTE_ARRAY(env, key, key_ptr);
        RELEASE_BYTE_ARRAY(env, nonce, nonce_ptr);
        RELEASE_BYTE_ARRAY(env, plaintext, pt_ptr);
        if (ad_jbyte) (*env)->ReleaseByteArrayElements(env, ad, ad_jbyte, JNI_ABORT);
        return NULL;
    }
    
    ewsp_error_t err = ewsp_aead_encrypt(
        (const uint8_t*)key_ptr,
        (const uint8_t*)nonce_ptr,
        ad_ptr, ad_len,
        (const uint8_t*)pt_ptr, pt_len,
        ciphertext
    );
    
    RELEASE_BYTE_ARRAY(env, key, key_ptr);
    RELEASE_BYTE_ARRAY(env, nonce, nonce_ptr);
    RELEASE_BYTE_ARRAY(env, plaintext, pt_ptr);
    if (ad_jbyte) (*env)->ReleaseByteArrayElements(env, ad, ad_jbyte, JNI_ABORT);
    
    if (err != EWSP_OK) {
        free(ciphertext);
        return NULL;
    }
    
    CREATE_BYTE_ARRAY(env, ciphertext, ct_len);
    free(ciphertext);
    return result;
}

/**
 * XChaCha20-Poly1305 authenticated decryption.
 * 
 * Expects ciphertext with 16-byte tag appended.
 * Returns NULL if authentication fails.
 * 
 * Kotlin: external fun aeadDecrypt(key: ByteArray, nonce: ByteArray,
 *                                   ciphertext: ByteArray, ad: ByteArray?): ByteArray?
 */
JNIEXPORT jbyteArray JNICALL
Java_org_wakelink_ewsp_CryptoNative_aeadDecrypt(JNIEnv *env, jobject thiz,
                                                 jbyteArray key, jbyteArray nonce,
                                                 jbyteArray ciphertext, jbyteArray ad) {
    (void)thiz;
    
    jsize key_len = (*env)->GetArrayLength(env, key);
    jsize nonce_len = (*env)->GetArrayLength(env, nonce);
    jsize ct_len = (*env)->GetArrayLength(env, ciphertext);
    
    if (key_len != 32 || nonce_len < 24 || ct_len < 16) return NULL;
    
    GET_BYTE_ARRAY(env, key, key_ptr, key_len2);
    GET_BYTE_ARRAY(env, nonce, nonce_ptr, nonce_len2);
    GET_BYTE_ARRAY(env, ciphertext, ct_ptr, ct_len2);
    (void)key_len2; (void)nonce_len2; (void)ct_len2;
    
    const uint8_t* ad_ptr = NULL;
    jsize ad_len = 0;
    jbyte* ad_jbyte = NULL;
    
    if (ad != NULL) {
        ad_jbyte = (*env)->GetByteArrayElements(env, ad, NULL);
        ad_ptr = (const uint8_t*)ad_jbyte;
        ad_len = (*env)->GetArrayLength(env, ad);
    }
    
    if (key_ptr == NULL || nonce_ptr == NULL || ct_ptr == NULL) {
        if (key_ptr) RELEASE_BYTE_ARRAY(env, key, key_ptr);
        if (nonce_ptr) RELEASE_BYTE_ARRAY(env, nonce, nonce_ptr);
        if (ct_ptr) RELEASE_BYTE_ARRAY(env, ciphertext, ct_ptr);
        if (ad_jbyte) (*env)->ReleaseByteArrayElements(env, ad, ad_jbyte, JNI_ABORT);
        return NULL;
    }
    
    size_t pt_len = ct_len - 16;  // plaintext without tag
    uint8_t* plaintext = (uint8_t*)malloc(pt_len);
    if (plaintext == NULL) {
        RELEASE_BYTE_ARRAY(env, key, key_ptr);
        RELEASE_BYTE_ARRAY(env, nonce, nonce_ptr);
        RELEASE_BYTE_ARRAY(env, ciphertext, ct_ptr);
        if (ad_jbyte) (*env)->ReleaseByteArrayElements(env, ad, ad_jbyte, JNI_ABORT);
        return NULL;
    }
    
    ewsp_error_t err = ewsp_aead_decrypt(
        (const uint8_t*)key_ptr,
        (const uint8_t*)nonce_ptr,
        ad_ptr, ad_len,
        (const uint8_t*)ct_ptr, ct_len,
        plaintext
    );
    
    RELEASE_BYTE_ARRAY(env, key, key_ptr);
    RELEASE_BYTE_ARRAY(env, nonce, nonce_ptr);
    RELEASE_BYTE_ARRAY(env, ciphertext, ct_ptr);
    if (ad_jbyte) (*env)->ReleaseByteArrayElements(env, ad, ad_jbyte, JNI_ABORT);
    
    if (err != EWSP_OK) {
        /* Authentication failed */
        free(plaintext);
        return NULL;
    }
    
    CREATE_BYTE_ARRAY(env, plaintext, pt_len);
    free(plaintext);
    return result;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * Generate cryptographically secure random bytes.
 * 
 * Kotlin: external fun randomBytes(size: Int): ByteArray
 */
JNIEXPORT jbyteArray JNICALL
Java_org_wakelink_ewsp_CryptoNative_randomBytes(JNIEnv *env, jobject thiz, jint size) {
    (void)thiz;
    
    if (size <= 0 || size > 1024 * 1024) return NULL;  // Sanity check: max 1MB
    
    uint8_t* buffer = (uint8_t*)malloc(size);
    if (buffer == NULL) return NULL;
    
    ewsp_error_t err = ewsp_random_bytes(buffer, size);
    if (err != EWSP_OK) {
        free(buffer);
        return NULL;
    }
    
    CREATE_BYTE_ARRAY(env, buffer, size);
    free(buffer);
    return result;
}

/**
 * Constant-time byte comparison.
 * 
 * Kotlin: external fun constantTimeCompare(a: ByteArray, b: ByteArray): Boolean
 */
JNIEXPORT jboolean JNICALL
Java_org_wakelink_ewsp_CryptoNative_constantTimeCompare(JNIEnv *env, jobject thiz,
                                                         jbyteArray a, jbyteArray b) {
    (void)thiz;
    
    jsize a_len = (*env)->GetArrayLength(env, a);
    jsize b_len = (*env)->GetArrayLength(env, b);
    
    if (a_len != b_len) return JNI_FALSE;
    
    GET_BYTE_ARRAY(env, a, a_ptr, a_len2);
    GET_BYTE_ARRAY(env, b, b_ptr, b_len2);
    (void)a_len2; (void)b_len2;
    
    if (a_ptr == NULL || b_ptr == NULL) {
        if (a_ptr) RELEASE_BYTE_ARRAY(env, a, a_ptr);
        if (b_ptr) RELEASE_BYTE_ARRAY(env, b, b_ptr);
        return JNI_FALSE;
    }
    
    int result = ewsp_constant_time_compare((const uint8_t*)a_ptr, 
                                             (const uint8_t*)b_ptr, a_len);
    
    RELEASE_BYTE_ARRAY(env, a, a_ptr);
    RELEASE_BYTE_ARRAY(env, b, b_ptr);
    
    return result ? JNI_TRUE : JNI_FALSE;
}

/* ============================================================================
 * JNI OnLoad
 * ============================================================================ */

/**
 * Called when native library is loaded.
 */
JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm;
    (void)reserved;
    
    /* Initialize ewsp-core */
    ewsp_init();
    
    return JNI_VERSION_1_6;
}

/**
 * Called when native library is unloaded.
 */
JNIEXPORT void JNI_OnUnload(JavaVM *vm, void *reserved) {
    (void)vm;
    (void)reserved;
    
    /* Cleanup ewsp-core */
    ewsp_cleanup();
}
