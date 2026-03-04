/**
 * @file ewsp_session.c
 * @brief EWSP Core Library - Secure Session Management Implementation
 * 
 * @author deadboizxc
 * @version 1.0
 */

#include "ewsp_session.h"
#include <string.h>

/* ============================================================================
 * Internal Helpers
 * ============================================================================ */

static void derive_session_keys(ewsp_session_t* session, const uint8_t master_key[32]) {
    /* Combine randoms: client_random || device_random */
    uint8_t ikm[EWSP_SESSION_RANDOM_SIZE * 2];
    memcpy(ikm, session->client_random, EWSP_SESSION_RANDOM_SIZE);
    memcpy(ikm + EWSP_SESSION_RANDOM_SIZE, session->device_random, EWSP_SESSION_RANDOM_SIZE);
    
    /* Derive session master key */
    ewsp_hkdf(master_key, 32, ikm, sizeof(ikm),
              (const uint8_t*)"wakelink_session_v2", 19,
              session->session_key, EWSP_SESSION_KEY_SIZE);
    
    /* Derive encryption key */
    ewsp_hkdf(session->session_key, EWSP_SESSION_KEY_SIZE, 
              NULL, 0,
              (const uint8_t*)"encryption", 10,
              session->enc_key, EWSP_SESSION_KEY_SIZE);
    
    /* Derive authentication key */
    ewsp_hkdf(session->session_key, EWSP_SESSION_KEY_SIZE,
              NULL, 0,
              (const uint8_t*)"authentication", 14,
              session->auth_key, EWSP_SESSION_KEY_SIZE);
    
    /* Derive binding key */
    ewsp_hkdf(session->session_key, EWSP_SESSION_KEY_SIZE,
              NULL, 0,
              (const uint8_t*)"binding", 7,
              session->binding_key, EWSP_SESSION_KEY_SIZE);
    
    /* Initialize ratchet key */
    memcpy(session->ratchet_key, session->session_key, EWSP_SESSION_KEY_SIZE);
    
    ewsp_secure_zero(ikm, sizeof(ikm));
}

static void calculate_proof(const uint8_t binding_key[32],
                            const uint8_t* first, size_t first_len,
                            const uint8_t* second, size_t second_len,
                            const uint8_t session_id[EWSP_SESSION_ID_SIZE],
                            uint8_t proof[32]) {
    /* proof = HMAC(binding_key, first || second || session_id) */
    uint8_t data[EWSP_SESSION_RANDOM_SIZE * 2 + EWSP_SESSION_ID_SIZE];
    memcpy(data, first, first_len);
    memcpy(data + first_len, second, second_len);
    memcpy(data + first_len + second_len, session_id, EWSP_SESSION_ID_SIZE);
    
    ewsp_hmac_sha256(binding_key, 32, data, sizeof(data), proof);
}

static ewsp_session_t* find_free_slot(ewsp_session_mgr_t* mgr) {
    for (int i = 0; i < EWSP_MAX_SESSIONS; i++) {
        ewsp_session_state_t state = mgr->sessions[i].state;
        if (state == EWSP_SESSION_IDLE ||
            state == EWSP_SESSION_EXPIRED ||
            state == EWSP_SESSION_TERMINATED ||
            state == EWSP_SESSION_REVOKED) {
            return &mgr->sessions[i];
        }
    }
    return NULL;
}

/* ============================================================================
 * Manager Lifecycle
 * ============================================================================ */

ewsp_error_t ewsp_session_mgr_init(ewsp_session_mgr_t* mgr, const uint8_t master_key[32]) {
    if (!mgr || !master_key) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    memset(mgr, 0, sizeof(*mgr));
    memcpy(mgr->master_key, master_key, 32);
    
    for (int i = 0; i < EWSP_MAX_SESSIONS; i++) {
        mgr->sessions[i].state = EWSP_SESSION_IDLE;
    }
    
    mgr->enabled = true;
    mgr->default_ratchet = true;
    mgr->initialized = true;
    
    return EWSP_OK;
}

void ewsp_session_mgr_cleanup(ewsp_session_mgr_t* mgr) {
    if (!mgr) return;
    
    for (int i = 0; i < EWSP_MAX_SESSIONS; i++) {
        ewsp_session_clear(&mgr->sessions[i]);
    }
    
    ewsp_secure_zero(mgr->master_key, 32);
    mgr->initialized = false;
}

void ewsp_session_mgr_tick(ewsp_session_mgr_t* mgr, uint32_t current_time) {
    if (!mgr || !mgr->initialized) return;
    
    for (int i = 0; i < EWSP_MAX_SESSIONS; i++) {
        ewsp_session_t* s = &mgr->sessions[i];
        if (s->state == EWSP_SESSION_IDLE) continue;
        
        /* Check handshake timeout */
        if (s->state == EWSP_SESSION_INIT || s->state == EWSP_SESSION_CHALLENGE) {
            if (current_time - s->handshake_started > EWSP_SESSION_HANDSHAKE_TIMEOUT) {
                s->state = EWSP_SESSION_EXPIRED;
                mgr->total_expired++;
            }
        }
        
        /* Check session expiration */
        if (s->state == EWSP_SESSION_ESTABLISHED || s->state == EWSP_SESSION_ACTIVE) {
            if (s->created_at > 0) {
                if (current_time - s->created_at > EWSP_SESSION_MAX_LIFETIME) {
                    s->state = EWSP_SESSION_EXPIRED;
                    mgr->total_expired++;
                } else if (current_time - s->last_activity > EWSP_SESSION_IDLE_TIMEOUT) {
                    s->state = EWSP_SESSION_EXPIRED;
                    mgr->total_expired++;
                }
            }
        }
    }
}

/* ============================================================================
 * Handshake - Server/Device Side
 * ============================================================================ */

ewsp_error_t ewsp_session_handle_init(ewsp_session_mgr_t* mgr,
                                       const ewsp_session_init_t* init,
                                       ewsp_session_challenge_t* challenge,
                                       uint32_t current_time) {
    if (!mgr || !mgr->initialized || !init || !challenge) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    /* Find free slot */
    ewsp_session_t* session = find_free_slot(mgr);
    if (!session) {
        /* Try cleanup and retry */
        ewsp_session_mgr_tick(mgr, current_time);
        session = find_free_slot(mgr);
        if (!session) {
            return EWSP_ERR_LIMIT_EXCEEDED;
        }
    }
    
    /* Clear and initialize */
    ewsp_session_clear(session);
    session->state = EWSP_SESSION_INIT;
    session->handshake_started = current_time;
    session->ratchet_enabled = mgr->default_ratchet;
    
    /* Store client random */
    memcpy(session->client_random, init->client_random, EWSP_SESSION_RANDOM_SIZE);
    
    /* Derive client_id from client_random (first 16 bytes of SHA-256) */
    uint8_t hash[32];
    ewsp_sha256(init->client_random, EWSP_SESSION_RANDOM_SIZE, hash);
    memcpy(session->client_id, hash, sizeof(session->client_id));
    
    /* Generate device random */
    ewsp_random_bytes(session->device_random, EWSP_SESSION_RANDOM_SIZE);
    
    /* Generate session_id */
    ewsp_random_bytes(session->session_id, EWSP_SESSION_ID_SIZE);
    
    /* Derive session keys */
    derive_session_keys(session, mgr->master_key);
    
    /* Calculate device proof: HMAC(binding_key, device_random || client_random || session_id) */
    uint8_t device_proof[32];
    calculate_proof(session->binding_key,
                    session->device_random, EWSP_SESSION_RANDOM_SIZE,
                    session->client_random, EWSP_SESSION_RANDOM_SIZE,
                    session->session_id, device_proof);
    
    /* Update state */
    session->state = EWSP_SESSION_CHALLENGE;
    
    /* Build challenge response */
    memcpy(challenge->session_id, session->session_id, EWSP_SESSION_ID_SIZE);
    memcpy(challenge->device_random, session->device_random, EWSP_SESSION_RANDOM_SIZE);
    memcpy(challenge->device_proof, device_proof, EWSP_SESSION_PROOF_SIZE);
    challenge->expires_in = EWSP_SESSION_HANDSHAKE_TIMEOUT;
    challenge->ratchet_enabled = session->ratchet_enabled;
    
    mgr->total_created++;
    
    return EWSP_OK;
}

ewsp_error_t ewsp_session_handle_confirm(ewsp_session_mgr_t* mgr,
                                          const ewsp_session_confirm_t* confirm,
                                          ewsp_session_established_t* established,
                                          uint32_t current_time) {
    if (!mgr || !mgr->initialized || !confirm || !established) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    /* Find session */
    ewsp_session_t* session = ewsp_session_get(mgr, confirm->session_id);
    if (!session) {
        mgr->auth_failures++;
        return EWSP_ERR_SESSION_EXPIRED;
    }
    
    /* Check state */
    if (session->state != EWSP_SESSION_CHALLENGE) {
        mgr->auth_failures++;
        return EWSP_ERR_SESSION_EXPIRED;
    }
    
    /* Check handshake timeout */
    if (current_time - session->handshake_started > EWSP_SESSION_HANDSHAKE_TIMEOUT) {
        session->state = EWSP_SESSION_EXPIRED;
        mgr->auth_failures++;
        return EWSP_ERR_TIMEOUT;
    }
    
    /* Calculate expected client proof: HMAC(binding_key, client_random || device_random || session_id) */
    uint8_t expected_proof[32];
    calculate_proof(session->binding_key,
                    session->client_random, EWSP_SESSION_RANDOM_SIZE,
                    session->device_random, EWSP_SESSION_RANDOM_SIZE,
                    session->session_id, expected_proof);
    
    /* Verify client proof (constant-time) */
    if (!ewsp_constant_time_compare(confirm->client_proof, expected_proof, EWSP_SESSION_PROOF_SIZE)) {
        session->failed_attempts++;
        mgr->auth_failures++;
        
        if (session->failed_attempts >= 3) {
            session->state = EWSP_SESSION_REVOKED;
            return EWSP_ERR_LOCKED_OUT;
        }
        
        return EWSP_ERR_AUTH_FAILED;
    }
    
    /* Session established! */
    session->state = EWSP_SESSION_ESTABLISHED;
    session->created_at = current_time;
    session->last_activity = current_time;
    session->send_counter = 0;
    session->recv_counter = 0;
    session->replay_bitmap = 0;
    session->ratchet_count = 0;
    
    /* Build established response */
    memcpy(established->session_id, session->session_id, EWSP_SESSION_ID_SIZE);
    established->expires_in = EWSP_SESSION_MAX_LIFETIME;
    established->idle_timeout = EWSP_SESSION_IDLE_TIMEOUT;
    established->ratchet_interval = session->ratchet_enabled ? EWSP_SESSION_RATCHET_INTERVAL : 0;
    
    /* Calculate binding token: HMAC(binding_key, session_id) */
    ewsp_hmac_sha256(session->binding_key, EWSP_SESSION_KEY_SIZE,
                     session->session_id, EWSP_SESSION_ID_SIZE,
                     established->binding_token);
    
    return EWSP_OK;
}

/* ============================================================================
 * Handshake - Client Side
 * ============================================================================ */

ewsp_error_t ewsp_session_create_init(const ewsp_session_mgr_t* mgr,
                                       const char* client_info,
                                       ewsp_session_init_t* init) {
    if (!mgr || !mgr->initialized || !init) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    memset(init, 0, sizeof(*init));
    
    /* Generate client random */
    ewsp_random_bytes(init->client_random, EWSP_SESSION_RANDOM_SIZE);
    
    /* Store client info */
    if (client_info) {
        size_t len = strlen(client_info);
        if (len >= sizeof(init->client_info)) {
            len = sizeof(init->client_info) - 1;
        }
        memcpy(init->client_info, client_info, len);
    }
    
    return EWSP_OK;
}

ewsp_error_t ewsp_session_process_challenge(ewsp_session_mgr_t* mgr,
                                             const ewsp_session_challenge_t* challenge,
                                             ewsp_session_confirm_t* confirm) {
    if (!mgr || !mgr->initialized || !challenge || !confirm) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    /* Find free slot for client session */
    ewsp_session_t* session = find_free_slot(mgr);
    if (!session) {
        return EWSP_ERR_LIMIT_EXCEEDED;
    }
    
    ewsp_session_clear(session);
    session->state = EWSP_SESSION_CHALLENGE;
    session->ratchet_enabled = challenge->ratchet_enabled;
    
    /* Copy challenge data to session */
    memcpy(session->session_id, challenge->session_id, EWSP_SESSION_ID_SIZE);
    memcpy(session->device_random, challenge->device_random, EWSP_SESSION_RANDOM_SIZE);
    
    /* Note: client_random was stored during create_init - we need to restore it */
    /* For client side, this is typically stored elsewhere or passed in */
    /* Here we assume the session was pre-populated with client_random */
    
    /* Derive keys */
    derive_session_keys(session, mgr->master_key);
    
    /* Verify device proof: HMAC(binding_key, device_random || client_random || session_id) */
    uint8_t expected_device_proof[32];
    calculate_proof(session->binding_key,
                    session->device_random, EWSP_SESSION_RANDOM_SIZE,
                    session->client_random, EWSP_SESSION_RANDOM_SIZE,
                    session->session_id, expected_device_proof);
    
    if (!ewsp_constant_time_compare(challenge->device_proof, expected_device_proof, EWSP_SESSION_PROOF_SIZE)) {
        ewsp_session_clear(session);
        mgr->auth_failures++;
        return EWSP_ERR_AUTH_FAILED;
    }
    
    /* Calculate client proof: HMAC(binding_key, client_random || device_random || session_id) */
    memcpy(confirm->session_id, session->session_id, EWSP_SESSION_ID_SIZE);
    calculate_proof(session->binding_key,
                    session->client_random, EWSP_SESSION_RANDOM_SIZE,
                    session->device_random, EWSP_SESSION_RANDOM_SIZE,
                    session->session_id, confirm->client_proof);
    
    return EWSP_OK;
}

ewsp_error_t ewsp_session_process_established(ewsp_session_mgr_t* mgr,
                                               const ewsp_session_established_t* established) {
    if (!mgr || !mgr->initialized || !established) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    ewsp_session_t* session = ewsp_session_get(mgr, established->session_id);
    if (!session || session->state != EWSP_SESSION_CHALLENGE) {
        return EWSP_ERR_SESSION_EXPIRED;
    }
    
    /* Verify binding token */
    uint8_t expected_token[32];
    ewsp_hmac_sha256(session->binding_key, EWSP_SESSION_KEY_SIZE,
                     session->session_id, EWSP_SESSION_ID_SIZE,
                     expected_token);
    
    if (!ewsp_constant_time_compare(established->binding_token, expected_token, EWSP_SESSION_PROOF_SIZE)) {
        ewsp_session_clear(session);
        mgr->auth_failures++;
        return EWSP_ERR_AUTH_FAILED;
    }
    
    /* Session fully established */
    session->state = EWSP_SESSION_ESTABLISHED;
    session->send_counter = 0;
    session->recv_counter = 0;
    session->replay_bitmap = 0;
    session->ratchet_count = 0;
    
    mgr->total_created++;
    
    return EWSP_OK;
}

/* ============================================================================
 * Session Operations
 * ============================================================================ */

ewsp_session_t* ewsp_session_get(ewsp_session_mgr_t* mgr, 
                                  const uint8_t session_id[EWSP_SESSION_ID_SIZE]) {
    if (!mgr || !session_id) return NULL;
    
    for (int i = 0; i < EWSP_MAX_SESSIONS; i++) {
        if (mgr->sessions[i].state != EWSP_SESSION_IDLE) {
            if (ewsp_constant_time_compare(mgr->sessions[i].session_id, 
                                           session_id, EWSP_SESSION_ID_SIZE)) {
                return &mgr->sessions[i];
            }
        }
    }
    return NULL;
}

ewsp_error_t ewsp_session_validate_counter(ewsp_session_t* session, uint64_t counter) {
    if (!session) return EWSP_ERR_INVALID_PARAMS;
    
    /* Counter must be higher than last received */
    if (counter <= session->recv_counter) {
        /* Check if within replay window */
        uint64_t diff = session->recv_counter - counter;
        if (diff >= EWSP_SESSION_REPLAY_WINDOW) {
            return EWSP_ERR_REPLAY_DETECTED;
        }
        
        /* Check bitmap */
        uint64_t bit = 1ULL << diff;
        if (session->replay_bitmap & bit) {
            return EWSP_ERR_REPLAY_DETECTED;
        }
        
        /* Mark as seen */
        session->replay_bitmap |= bit;
    } else {
        /* New highest - shift window */
        uint64_t shift = counter - session->recv_counter;
        if (shift < 64) {
            session->replay_bitmap <<= shift;
            session->replay_bitmap |= 1;
        } else {
            session->replay_bitmap = 1;
        }
        session->recv_counter = counter;
    }
    
    return EWSP_OK;
}

ewsp_error_t ewsp_session_terminate(ewsp_session_mgr_t* mgr,
                                     const uint8_t session_id[EWSP_SESSION_ID_SIZE]) {
    ewsp_session_t* session = ewsp_session_get(mgr, session_id);
    if (!session) return EWSP_ERR_SESSION_EXPIRED;
    
    ewsp_session_clear(session);
    session->state = EWSP_SESSION_TERMINATED;
    return EWSP_OK;
}

void ewsp_session_revoke_all(ewsp_session_mgr_t* mgr) {
    if (!mgr) return;
    
    for (int i = 0; i < EWSP_MAX_SESSIONS; i++) {
        if (mgr->sessions[i].state != EWSP_SESSION_IDLE) {
            ewsp_session_clear(&mgr->sessions[i]);
        }
    }
}

/* ============================================================================
 * Encryption/Decryption
 * ============================================================================ */

size_t ewsp_session_encrypt(ewsp_session_t* session,
                            const uint8_t* plaintext, size_t plaintext_len,
                            const uint8_t* ad, size_t ad_len,
                            uint8_t* ciphertext,
                            uint64_t* counter) {
    if (!session || !ciphertext || !counter) return 0;
    if (session->state != EWSP_SESSION_ESTABLISHED && session->state != EWSP_SESSION_ACTIVE) {
        return 0;
    }
    if (plaintext_len > 0 && !plaintext) return 0;
    
    /* Get and increment counter */
    *counter = session->send_counter++;
    session->ratchet_count++;
    
    /* Generate nonce */
    uint8_t nonce[EWSP_AEAD_NONCE_SIZE];
    ewsp_random_bytes(nonce, EWSP_AEAD_NONCE_SIZE);
    
    /* Encrypt with AEAD */
    ewsp_error_t err = ewsp_aead_encrypt(session->enc_key, nonce,
                                          ad, ad_len,
                                          plaintext, plaintext_len,
                                          ciphertext);
    if (err != EWSP_OK) return 0;
    
    /* Append nonce */
    memcpy(ciphertext + plaintext_len + EWSP_AEAD_TAG_SIZE, nonce, EWSP_AEAD_NONCE_SIZE);
    
    /* Update state */
    session->state = EWSP_SESSION_ACTIVE;
    session->packets_sent++;
    
    /* Auto-ratchet if needed */
    if (session->ratchet_enabled && session->ratchet_count >= EWSP_SESSION_RATCHET_INTERVAL) {
        ewsp_session_ratchet(session);
        session->ratchet_count = 0;
    }
    
    return plaintext_len + EWSP_AEAD_TAG_SIZE + EWSP_AEAD_NONCE_SIZE;
}

size_t ewsp_session_decrypt(ewsp_session_t* session,
                            const uint8_t* ciphertext, size_t ciphertext_len,
                            const uint8_t* ad, size_t ad_len,
                            uint8_t* plaintext,
                            uint64_t counter) {
    if (!session || !ciphertext || !plaintext) return 0;
    if (session->state != EWSP_SESSION_ESTABLISHED && session->state != EWSP_SESSION_ACTIVE) {
        return 0;
    }
    
    /* Minimum size: tag + nonce */
    if (ciphertext_len < EWSP_AEAD_TAG_SIZE + EWSP_AEAD_NONCE_SIZE) {
        return 0;
    }
    
    /* Validate counter (replay protection) */
    if (ewsp_session_validate_counter(session, counter) != EWSP_OK) {
        return 0;
    }
    
    /* Extract nonce from end */
    size_t ct_and_tag_len = ciphertext_len - EWSP_AEAD_NONCE_SIZE;
    const uint8_t* nonce = ciphertext + ct_and_tag_len;
    
    /* Decrypt with AEAD */
    ewsp_error_t err = ewsp_aead_decrypt(session->enc_key, nonce,
                                          ad, ad_len,
                                          ciphertext, ct_and_tag_len,
                                          plaintext);
    if (err != EWSP_OK) return 0;
    
    /* Update state */
    session->state = EWSP_SESSION_ACTIVE;
    session->packets_received++;
    
    return ct_and_tag_len - EWSP_AEAD_TAG_SIZE;
}

/* ============================================================================
 * Key Ratchet
 * ============================================================================ */

void ewsp_session_ratchet(ewsp_session_t* session) {
    if (!session) return;
    
    /* Ratchet: new_key = HKDF(current_key, counter, "ratchet") */
    uint8_t counter_bytes[8];
    memcpy(counter_bytes, &session->send_counter, 8);
    
    uint8_t new_key[EWSP_SESSION_KEY_SIZE];
    ewsp_hkdf(session->ratchet_key, EWSP_SESSION_KEY_SIZE,
              counter_bytes, 8,
              (const uint8_t*)"ratchet", 7,
              new_key, EWSP_SESSION_KEY_SIZE);
    
    memcpy(session->ratchet_key, new_key, EWSP_SESSION_KEY_SIZE);
    
    /* Derive new enc_key and auth_key from ratchet */
    ewsp_hkdf(session->ratchet_key, EWSP_SESSION_KEY_SIZE,
              NULL, 0,
              (const uint8_t*)"ratchet_enc", 11,
              session->enc_key, EWSP_SESSION_KEY_SIZE);
    
    ewsp_hkdf(session->ratchet_key, EWSP_SESSION_KEY_SIZE,
              NULL, 0,
              (const uint8_t*)"ratchet_auth", 12,
              session->auth_key, EWSP_SESSION_KEY_SIZE);
    
    ewsp_secure_zero(new_key, sizeof(new_key));
}

/* ============================================================================
 * Utility
 * ============================================================================ */

uint8_t ewsp_session_active_count(const ewsp_session_mgr_t* mgr) {
    if (!mgr) return 0;
    
    uint8_t count = 0;
    for (int i = 0; i < EWSP_MAX_SESSIONS; i++) {
        ewsp_session_state_t state = mgr->sessions[i].state;
        if (state == EWSP_SESSION_ESTABLISHED || state == EWSP_SESSION_ACTIVE) {
            count++;
        }
    }
    return count;
}

void ewsp_session_clear(ewsp_session_t* session) {
    if (!session) return;
    
    ewsp_secure_zero(session->session_key, EWSP_SESSION_KEY_SIZE);
    ewsp_secure_zero(session->enc_key, EWSP_SESSION_KEY_SIZE);
    ewsp_secure_zero(session->auth_key, EWSP_SESSION_KEY_SIZE);
    ewsp_secure_zero(session->binding_key, EWSP_SESSION_KEY_SIZE);
    ewsp_secure_zero(session->ratchet_key, EWSP_SESSION_KEY_SIZE);
    ewsp_secure_zero(session->client_random, EWSP_SESSION_RANDOM_SIZE);
    ewsp_secure_zero(session->device_random, EWSP_SESSION_RANDOM_SIZE);
    
    memset(session, 0, sizeof(*session));
    session->state = EWSP_SESSION_IDLE;
}
