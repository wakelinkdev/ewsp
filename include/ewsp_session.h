/**
 * @file ewsp_session.h
 * @brief EWSP Core Library - Secure Session Management
 * 
 * Pentagon-grade session security with:
 * - Mutual authentication (challenge-response)
 * - Key derivation via HKDF-SHA256
 * - Forward secrecy (key ratcheting)
 * - Replay protection (64-bit counters + bitmap)
 * - Session binding tokens
 * 
 * Compatible with:
 * - wakelink-firmware SessionManager.cpp
 * - wakelink-client session_manager.py
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * SESSION HANDSHAKE PROTOCOL
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * Client                              Device
 *   |                                   |
 *   |-- session_init {client_random} -->|
 *   |                                   | Generate device_random, session_id
 *   |                                   | Derive keys
 *   |<-- session_challenge -------------|
 *   |    {session_id, device_random,    |
 *   |     device_proof, expires_in}     |
 *   |                                   |
 *   | Verify device_proof               |
 *   | Calculate client_proof            |
 *   |                                   |
 *   |-- session_confirm --------------->|
 *   |   {session_id, client_proof}      |
 *   |                                   | Verify client_proof
 *   |<-- session_established -----------|
 *   |    {binding_token, expires}       |
 *   |                                   |
 *   | Session ready for encrypted       |
 *   | communication using AEAD          |
 * 
 * @author deadboizxc
 * @version 1.0
 */

#ifndef EWSP_SESSION_H
#define EWSP_SESSION_H

#include "ewsp_types.h"
#include "ewsp_errors.h"
#include "ewsp_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Constants
 * ============================================================================ */

/** Session ID size in bytes */
#define EWSP_SESSION_ID_SIZE        16

/** Random challenge size in bytes */
#define EWSP_SESSION_RANDOM_SIZE    32

/** Session key size in bytes */
#define EWSP_SESSION_KEY_SIZE       32

/** Proof/binding token size in bytes */
#define EWSP_SESSION_PROOF_SIZE     32

/** Maximum concurrent sessions */
#define EWSP_MAX_SESSIONS           4

/** Handshake timeout in seconds */
#define EWSP_SESSION_HANDSHAKE_TIMEOUT  30

/** Session idle timeout in seconds */
#define EWSP_SESSION_IDLE_TIMEOUT   300

/** Maximum session lifetime in seconds */
#define EWSP_SESSION_MAX_LIFETIME   86400

/** Key ratchet interval (messages) */
#define EWSP_SESSION_RATCHET_INTERVAL 100

/** Replay window size in packets */
#define EWSP_SESSION_REPLAY_WINDOW  64

/* ============================================================================
 * Session State
 * ============================================================================ */

/**
 * @brief Session state machine states.
 */
typedef enum {
    EWSP_SESSION_IDLE = 0,      /**< Slot is free */
    EWSP_SESSION_INIT,          /**< Init received, awaiting confirm */
    EWSP_SESSION_CHALLENGE,     /**< Challenge sent, awaiting confirm */
    EWSP_SESSION_ESTABLISHED,   /**< Handshake complete, ready to use */
    EWSP_SESSION_ACTIVE,        /**< Currently in use */
    EWSP_SESSION_EXPIRED,       /**< Timed out */
    EWSP_SESSION_TERMINATED,    /**< Cleanly closed */
    EWSP_SESSION_REVOKED        /**< Revoked due to security event */
} ewsp_session_state_t;

/* ============================================================================
 * Session Structure
 * ============================================================================ */

/**
 * @brief Individual session information.
 */
typedef struct {
    ewsp_session_state_t state;             /**< Current state */
    
    /* Identity */
    uint8_t session_id[EWSP_SESSION_ID_SIZE];    /**< Unique session identifier */
    uint8_t client_id[16];                       /**< Client identifier (derived) */
    
    /* Handshake data */
    uint8_t client_random[EWSP_SESSION_RANDOM_SIZE];  /**< Client's random */
    uint8_t device_random[EWSP_SESSION_RANDOM_SIZE];  /**< Device's random */
    
    /* Derived keys (from HKDF) */
    uint8_t session_key[EWSP_SESSION_KEY_SIZE];  /**< Master session key */
    uint8_t enc_key[EWSP_SESSION_KEY_SIZE];      /**< Encryption key (XChaCha20) */
    uint8_t auth_key[EWSP_SESSION_KEY_SIZE];     /**< Authentication key (HMAC) */
    uint8_t binding_key[EWSP_SESSION_KEY_SIZE];  /**< Binding/proof key */
    uint8_t ratchet_key[EWSP_SESSION_KEY_SIZE];  /**< Current ratchet state */
    
    /* Counters */
    uint64_t send_counter;                  /**< Outgoing message counter */
    uint64_t recv_counter;                  /**< Incoming message counter */
    uint64_t replay_bitmap;                 /**< Replay detection bitmap */
    
    /* Timing */
    uint32_t created_at;                    /**< Session creation time */
    uint32_t last_activity;                 /**< Last message time */
    uint32_t handshake_started;             /**< Handshake start time */
    
    /* Statistics */
    uint32_t packets_sent;                  /**< Total packets sent */
    uint32_t packets_received;              /**< Total packets received */
    uint8_t failed_attempts;                /**< Auth failure count */
    
    /* Options */
    bool ratchet_enabled;                   /**< Enable forward secrecy */
    uint16_t ratchet_count;                 /**< Messages since last ratchet */
} ewsp_session_t;

/**
 * @brief Session manager context.
 */
typedef struct {
    uint8_t master_key[32];                 /**< Device master key */
    ewsp_session_t sessions[EWSP_MAX_SESSIONS]; /**< Session slots */
    bool initialized;                       /**< Manager ready */
    bool enabled;                           /**< Sessions enabled */
    bool default_ratchet;                   /**< Default ratchet setting */
    
    /* Statistics */
    uint32_t total_created;                 /**< Total sessions created */
    uint32_t total_expired;                 /**< Total sessions expired */
    uint32_t auth_failures;                 /**< Total auth failures */
    uint32_t replay_attempts;               /**< Total replay attempts */
} ewsp_session_mgr_t;

/* ============================================================================
 * Handshake Data Structures
 * ============================================================================ */

/**
 * @brief Session init request data.
 */
typedef struct {
    uint8_t client_random[EWSP_SESSION_RANDOM_SIZE];
    char client_info[64];
} ewsp_session_init_t;

/**
 * @brief Session challenge response data.
 */
typedef struct {
    uint8_t session_id[EWSP_SESSION_ID_SIZE];
    uint8_t device_random[EWSP_SESSION_RANDOM_SIZE];
    uint8_t device_proof[EWSP_SESSION_PROOF_SIZE];
    uint32_t expires_in;
    bool ratchet_enabled;
} ewsp_session_challenge_t;

/**
 * @brief Session confirm request data.
 */
typedef struct {
    uint8_t session_id[EWSP_SESSION_ID_SIZE];
    uint8_t client_proof[EWSP_SESSION_PROOF_SIZE];
} ewsp_session_confirm_t;

/**
 * @brief Session established response data.
 */
typedef struct {
    uint8_t session_id[EWSP_SESSION_ID_SIZE];
    uint8_t binding_token[EWSP_SESSION_PROOF_SIZE];
    uint32_t expires_in;
    uint32_t idle_timeout;
    uint16_t ratchet_interval;
} ewsp_session_established_t;

/* ============================================================================
 * Manager Lifecycle
 * ============================================================================ */

/**
 * @brief Initialize session manager.
 * @param mgr Manager to initialize.
 * @param master_key 32-byte device master key.
 * @return EWSP_OK on success.
 */
ewsp_error_t ewsp_session_mgr_init(ewsp_session_mgr_t* mgr, const uint8_t master_key[32]);

/**
 * @brief Cleanup session manager (secure zeroing).
 */
void ewsp_session_mgr_cleanup(ewsp_session_mgr_t* mgr);

/**
 * @brief Periodic maintenance (call every ~10 seconds).
 * 
 * Cleans up expired sessions.
 * 
 * @param mgr Session manager.
 * @param current_time Current time in seconds.
 */
void ewsp_session_mgr_tick(ewsp_session_mgr_t* mgr, uint32_t current_time);

/* ============================================================================
 * Handshake - Server/Device Side
 * ============================================================================ */

/**
 * @brief Handle session_init request (device side).
 * 
 * @param mgr Session manager.
 * @param init Init request data.
 * @param challenge Output challenge response.
 * @param current_time Current time in seconds.
 * @return EWSP_OK on success.
 */
ewsp_error_t ewsp_session_handle_init(ewsp_session_mgr_t* mgr,
                                       const ewsp_session_init_t* init,
                                       ewsp_session_challenge_t* challenge,
                                       uint32_t current_time);

/**
 * @brief Handle session_confirm request (device side).
 * 
 * @param mgr Session manager.
 * @param confirm Confirm request data.
 * @param established Output established response.
 * @param current_time Current time in seconds.
 * @return EWSP_OK on success, EWSP_ERR_AUTH_FAILED on bad proof.
 */
ewsp_error_t ewsp_session_handle_confirm(ewsp_session_mgr_t* mgr,
                                          const ewsp_session_confirm_t* confirm,
                                          ewsp_session_established_t* established,
                                          uint32_t current_time);

/* ============================================================================
 * Handshake - Client Side
 * ============================================================================ */

/**
 * @brief Create session_init request (client side).
 * 
 * @param mgr Session manager.
 * @param client_info Optional client identification.
 * @param init Output init request to send.
 * @return EWSP_OK on success.
 */
ewsp_error_t ewsp_session_create_init(ewsp_session_mgr_t* mgr,
                                       const char* client_info,
                                       ewsp_session_init_t* init);

/**
 * @brief Process session_challenge response (client side).
 * 
 * Verifies device_proof and prepares client_proof.
 * 
 * @param mgr Session manager.
 * @param challenge Received challenge.
 * @param confirm Output confirm request to send.
 * @return EWSP_OK on success, EWSP_ERR_AUTH_FAILED if device_proof invalid.
 */
ewsp_error_t ewsp_session_process_challenge(ewsp_session_mgr_t* mgr,
                                             const ewsp_session_challenge_t* challenge,
                                             ewsp_session_confirm_t* confirm);

/**
 * @brief Process session_established response (client side).
 * 
 * @param mgr Session manager.
 * @param established Received response.
 * @return EWSP_OK on success.
 */
ewsp_error_t ewsp_session_process_established(ewsp_session_mgr_t* mgr,
                                               const ewsp_session_established_t* established);

/* ============================================================================
 * Session Operations
 * ============================================================================ */

/**
 * @brief Get active session by ID.
 * 
 * @param mgr Session manager.
 * @param session_id 16-byte session ID.
 * @return Pointer to session or NULL if not found.
 */
ewsp_session_t* ewsp_session_get(ewsp_session_mgr_t* mgr, 
                                  const uint8_t session_id[EWSP_SESSION_ID_SIZE]);

/**
 * @brief Validate incoming message counter (replay protection).
 * 
 * @param session Session to validate against.
 * @param counter Message counter from incoming packet.
 * @return EWSP_OK if valid, EWSP_ERR_REPLAY_DETECTED if replayed.
 */
ewsp_error_t ewsp_session_validate_counter(ewsp_session_t* session, uint64_t counter);

/**
 * @brief Terminate session.
 * 
 * @param mgr Session manager.
 * @param session_id Session to terminate.
 * @return EWSP_OK on success.
 */
ewsp_error_t ewsp_session_terminate(ewsp_session_mgr_t* mgr,
                                     const uint8_t session_id[EWSP_SESSION_ID_SIZE]);

/**
 * @brief Revoke all sessions (security event).
 */
void ewsp_session_revoke_all(ewsp_session_mgr_t* mgr);

/* ============================================================================
 * Encryption/Decryption
 * ============================================================================ */

/**
 * @brief Encrypt data for session using XChaCha20-Poly1305 AEAD.
 * 
 * @param session Active session.
 * @param plaintext Input data.
 * @param plaintext_len Length of input.
 * @param ad Associated data (e.g., packet header).
 * @param ad_len Length of AD.
 * @param ciphertext Output buffer (size = plaintext_len + 16 tag + 24 nonce).
 * @param counter Output message counter used.
 * @return Bytes written to ciphertext, or 0 on error.
 */
size_t ewsp_session_encrypt(ewsp_session_t* session,
                            const uint8_t* plaintext, size_t plaintext_len,
                            const uint8_t* ad, size_t ad_len,
                            uint8_t* ciphertext,
                            uint64_t* counter);

/**
 * @brief Decrypt data from session using XChaCha20-Poly1305 AEAD.
 * 
 * @param session Active session.
 * @param ciphertext Input (ciphertext + 16 tag + 24 nonce).
 * @param ciphertext_len Total length.
 * @param ad Associated data (must match encryption).
 * @param ad_len Length of AD.
 * @param plaintext Output buffer.
 * @param counter Message counter from packet.
 * @return Bytes written to plaintext, or 0 on error (auth failure).
 */
size_t ewsp_session_decrypt(ewsp_session_t* session,
                            const uint8_t* ciphertext, size_t ciphertext_len,
                            const uint8_t* ad, size_t ad_len,
                            uint8_t* plaintext,
                            uint64_t counter);

/* ============================================================================
 * Key Ratchet
 * ============================================================================ */

/**
 * @brief Perform key ratchet for forward secrecy.
 * 
 * Called automatically after EWSP_SESSION_RATCHET_INTERVAL messages
 * when ratchet_enabled is true.
 * 
 * @param session Session to ratchet.
 */
void ewsp_session_ratchet(ewsp_session_t* session);

/* ============================================================================
 * Utility
 * ============================================================================ */

/**
 * @brief Check if session is valid and not expired.
 */
static inline bool ewsp_session_is_valid(const ewsp_session_t* session, uint32_t current_time) {
    if (!session) return false;
    if (session->state != EWSP_SESSION_ESTABLISHED && session->state != EWSP_SESSION_ACTIVE) {
        return false;
    }
    if (session->created_at > 0) {
        if (current_time - session->created_at > EWSP_SESSION_MAX_LIFETIME) return false;
        if (current_time - session->last_activity > EWSP_SESSION_IDLE_TIMEOUT) return false;
    }
    return true;
}

/**
 * @brief Get number of active sessions.
 */
uint8_t ewsp_session_active_count(const ewsp_session_mgr_t* mgr);

/**
 * @brief Clear session (secure zero all sensitive data).
 */
void ewsp_session_clear(ewsp_session_t* session);

#ifdef __cplusplus
}
#endif

#endif /* EWSP_SESSION_H */
