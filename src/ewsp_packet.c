/**
 * @file ewsp_packet.c
 * @brief EWSP Core Library - Packet Manager Implementation
 * 
 * @author deadboizxc
 * @version 1.0
 */

#include "ewsp_packet.h"
#include "ewsp_json.h"
#include <stdio.h>
#include <stdlib.h>

/* ============================================================================
 * Context Management
 * ============================================================================ */

ewsp_error_t ewsp_packet_init(ewsp_packet_ctx* ctx,
                               const char* token,
                               const char* device_id) {
    if (!ctx || !token || !device_id) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    memset(ctx, 0, sizeof(*ctx));
    
    /* Initialize crypto */
    ewsp_error_t err = ewsp_crypto_init(&ctx->crypto, token, strlen(token));
    if (err != EWSP_OK) {
        return err;
    }
    
    /* Initialize chain */
    ewsp_chain_ctx_init(&ctx->chain);
    
    /* Copy device ID */
    size_t id_len = strlen(device_id);
    if (id_len > EWSP_MAX_DEVICE_ID_LEN) {
        id_len = EWSP_MAX_DEVICE_ID_LEN;
    }
    memcpy(ctx->device_id, device_id, id_len);
    ctx->device_id[id_len] = '\0';
    
    ctx->initialized = true;
    return EWSP_OK;
}

void ewsp_packet_cleanup(ewsp_packet_ctx* ctx) {
    if (!ctx) return;
    
    ewsp_crypto_cleanup(&ctx->crypto);
    ewsp_chain_ctx_reset(&ctx->chain);
    ewsp_secure_memzero(ctx->device_id, sizeof(ctx->device_id));
    ctx->initialized = false;
}

void ewsp_packet_reset_chains(ewsp_packet_ctx* ctx) {
    if (!ctx) return;
    ewsp_chain_ctx_reset(&ctx->chain);
}

/* ============================================================================
 * Request ID Generation
 * ============================================================================ */

void ewsp_packet_generate_rid(char rid_out[9]) {
    static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    uint8_t random_bytes[8];
    
    ewsp_random_bytes(random_bytes, 8);
    
    for (int i = 0; i < 8; i++) {
        rid_out[i] = chars[random_bytes[i] % (sizeof(chars) - 1)];
    }
    rid_out[8] = '\0';
}

/* ============================================================================
 * Packet Creation
 * ============================================================================ */

ewsp_error_t ewsp_packet_create_command(ewsp_packet_ctx* ctx,
                                         const char* command,
                                         const char* data_json,
                                         char* packet_out,
                                         size_t packet_out_size) {
    if (!ctx || !ctx->initialized || !command || !packet_out) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    /* Build inner JSON: {"cmd":"...", "d":{...}, "rid":"..."} */
    char inner_json[EWSP_MAX_INNER_JSON];
    ewsp_json_writer_t w;
    ewsp_json_writer_init(&w, inner_json, sizeof(inner_json));
    
    ewsp_json_write_object_start(&w);
    ewsp_json_write_kv_string(&w, "cmd", command);
    
    /* Write data field */
    ewsp_json_write_key(&w, "d");
    if (data_json && data_json[0] != '\0') {
        ewsp_json_write_raw(&w, data_json);
    } else {
        ewsp_json_write_raw(&w, "{}");
    }
    
    /* Generate and write request ID */
    char rid[9];
    ewsp_packet_generate_rid(rid);
    ewsp_json_write_kv_string(&w, "rid", rid);
    
    ewsp_json_write_object_end(&w);
    ewsp_json_writer_finish(&w);
    
    if (ewsp_json_writer_has_error(&w)) {
        return EWSP_ERR_BUFFER_TOO_SMALL;
    }
    
    /* Create packet with TX chain link */
    return ewsp_packet_create(ctx, inner_json, true, packet_out, packet_out_size);
}

ewsp_error_t ewsp_packet_create_response(ewsp_packet_ctx* ctx,
                                          const char* response_json,
                                          char* packet_out,
                                          size_t packet_out_size) {
    if (!ctx || !ctx->initialized || !response_json || !packet_out) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    /* Response uses last_received_hash as prev */
    return ewsp_packet_create(ctx, response_json, false, packet_out, packet_out_size);
}

ewsp_error_t ewsp_packet_create(ewsp_packet_ctx* ctx,
                                 const char* inner_json,
                                 bool use_request_prev,
                                 char* packet_out,
                                 size_t packet_out_size) {
    if (!ctx || !ctx->initialized || !inner_json || !packet_out) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    /* Increment sequence */
    ewsp_seq_t seq = ewsp_chain_next_tx_seq(&ctx->chain);
    
    /* Get prev_hash */
    const char* prev_hash;
    if (use_request_prev) {
        prev_hash = ewsp_chain_tx_hash(&ctx->chain);
    } else {
        prev_hash = ewsp_chain_last_received_hash(&ctx->chain);
    }
    
    /* Encrypt inner JSON */
    char payload_hex[EWSP_MAX_PAYLOAD_SIZE * 2 + 1];
    ewsp_error_t err = ewsp_crypto_encrypt(&ctx->crypto,
                                            (const uint8_t*)inner_json,
                                            strlen(inner_json),
                                            payload_hex,
                                            sizeof(payload_hex));
    if (err != EWSP_OK) {
        return err;
    }
    
    /* Build signature data: "v|id|seq|prev|p" */
    char sig_data[EWSP_MAX_OUTER_JSON];
    int sig_data_len = snprintf(sig_data, sizeof(sig_data),
                                 "1.0|%s|%llu|%s|%s",
                                 ctx->device_id,
                                 (unsigned long long)seq,
                                 prev_hash,
                                 payload_hex);
    
    if (sig_data_len < 0 || (size_t)sig_data_len >= sizeof(sig_data)) {
        return EWSP_ERR_BUFFER_TOO_SMALL;
    }
    
    /* Calculate HMAC signature */
    char signature_hex[65];
    ewsp_crypto_sign(&ctx->crypto, (const uint8_t*)sig_data, strlen(sig_data), signature_hex);
    
    /* Build outer JSON */
    ewsp_json_writer_t w;
    ewsp_json_writer_init(&w, packet_out, packet_out_size);
    
    ewsp_json_write_object_start(&w);
    ewsp_json_write_kv_string(&w, "v", "1.0");
    ewsp_json_write_kv_string(&w, "id", ctx->device_id);
    ewsp_json_write_kv_uint(&w, "seq", seq);
    ewsp_json_write_kv_string(&w, "prev", prev_hash);
    ewsp_json_write_kv_string(&w, "p", payload_hex);
    ewsp_json_write_kv_string(&w, "sig", signature_hex);
    ewsp_json_write_object_end(&w);
    ewsp_json_writer_finish(&w);
    
    if (ewsp_json_writer_has_error(&w)) {
        return EWSP_ERR_BUFFER_TOO_SMALL;
    }
    
    /* Update TX chain with hash of new packet */
    char packet_hash[65];
    ewsp_chain_hash_packet(packet_out, packet_hash);
    ewsp_chain_update_tx(&ctx->chain, seq, packet_hash);
    
    return EWSP_OK;
}

/* ============================================================================
 * Packet Processing
 * ============================================================================ */

ewsp_error_t ewsp_packet_parse_outer(const char* packet_json,
                                      ewsp_outer_packet_t* outer) {
    if (!packet_json || !outer) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    ewsp_outer_packet_init(outer);
    
    ewsp_json_reader_t r;
    ewsp_json_reader_init(&r, packet_json, strlen(packet_json));
    
    /* Parse version */
    ewsp_error_t err = ewsp_json_get_string(&r, "v", outer->version, sizeof(outer->version));
    if (err != EWSP_OK) {
        return EWSP_ERR_BAD_PACKET;
    }
    
    /* Parse device_id */
    err = ewsp_json_get_string(&r, "id", outer->device_id, sizeof(outer->device_id));
    if (err != EWSP_OK) {
        return EWSP_ERR_BAD_PACKET;
    }
    
    /* Parse sequence */
    uint64_t seq;
    err = ewsp_json_get_uint(&r, "seq", &seq);
    if (err != EWSP_OK) {
        return EWSP_ERR_BAD_PACKET;
    }
    outer->sequence = seq;
    
    /* Parse prev_hash */
    err = ewsp_json_get_string(&r, "prev", outer->prev_hash, sizeof(outer->prev_hash));
    if (err != EWSP_OK) {
        return EWSP_ERR_BAD_PACKET;
    }
    
    /* Parse payload */
    err = ewsp_json_get_string(&r, "p", outer->payload, sizeof(outer->payload));
    if (err != EWSP_OK) {
        return EWSP_ERR_BAD_PACKET;
    }
    
    /* Parse signature */
    err = ewsp_json_get_string(&r, "sig", outer->signature, sizeof(outer->signature));
    if (err != EWSP_OK) {
        return EWSP_ERR_BAD_PACKET;
    }
    
    return EWSP_OK;
}

ewsp_error_t ewsp_packet_build_sig_data(const ewsp_outer_packet_t* outer,
                                         char* sig_data_out,
                                         size_t sig_data_size) {
    if (!outer || !sig_data_out) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    int len = snprintf(sig_data_out, sig_data_size,
                       "%s|%s|%llu|%s|%s",
                       outer->version,
                       outer->device_id,
                       (unsigned long long)outer->sequence,
                       outer->prev_hash,
                       outer->payload);
    
    if (len < 0 || (size_t)len >= sig_data_size) {
        return EWSP_ERR_BUFFER_TOO_SMALL;
    }
    
    return EWSP_OK;
}

bool ewsp_packet_verify_signature(const ewsp_crypto_ctx* crypto,
                                   const char* packet_json) {
    if (!crypto || !crypto->initialized || !packet_json) {
        return false;
    }
    
    /* Parse outer packet */
    ewsp_outer_packet_t outer;
    if (ewsp_packet_parse_outer(packet_json, &outer) != EWSP_OK) {
        return false;
    }
    
    /* Build signature data */
    char sig_data[EWSP_MAX_OUTER_JSON];
    if (ewsp_packet_build_sig_data(&outer, sig_data, sizeof(sig_data)) != EWSP_OK) {
        return false;
    }
    
    /* Verify */
    return ewsp_crypto_verify(crypto, (const uint8_t*)sig_data, strlen(sig_data), outer.signature);
}

ewsp_error_t ewsp_packet_process(ewsp_packet_ctx* ctx,
                                  const char* packet_json,
                                  ewsp_packet_result_t* result) {
    if (!ctx || !ctx->initialized || !packet_json || !result) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    ewsp_packet_result_init(result);
    
    /* Step 1: Parse outer packet */
    ewsp_outer_packet_t outer;
    ewsp_error_t err = ewsp_packet_parse_outer(packet_json, &outer);
    if (err != EWSP_OK) {
        result->error = err;
        strcpy(result->error_detail, "Failed to parse outer JSON");
        return err;
    }
    
    /* Step 2: Check protocol version */
    if (strcmp(outer.version, "1.0") != 0) {
        result->error = EWSP_ERR_BAD_VERSION;
        snprintf(result->error_detail, sizeof(result->error_detail),
                 "Expected v1.0, got %s", outer.version);
        return EWSP_ERR_BAD_VERSION;
    }
    
    /* Step 3: Verify signature */
    char sig_data[EWSP_MAX_OUTER_JSON];
    err = ewsp_packet_build_sig_data(&outer, sig_data, sizeof(sig_data));
    if (err != EWSP_OK) {
        result->error = err;
        return err;
    }
    
    if (!ewsp_crypto_verify(&ctx->crypto, (const uint8_t*)sig_data, strlen(sig_data), outer.signature)) {
        result->error = EWSP_ERR_INVALID_SIGNATURE;
        strcpy(result->error_detail, "HMAC signature verification failed");
        return EWSP_ERR_INVALID_SIGNATURE;
    }
    
    /* Step 4: Validate chain (sequence and prev_hash) */
    err = ewsp_chain_validate(&ctx->chain, outer.sequence, outer.prev_hash);
    if (err != EWSP_OK) {
        result->error = err;
        if (err == EWSP_ERR_REPLAY_DETECTED) {
            snprintf(result->error_detail, sizeof(result->error_detail),
                     "seq must be > %llu", (unsigned long long)ctx->chain.rx.sequence);
        } else if (err == EWSP_ERR_CHAIN_BROKEN) {
            snprintf(result->error_detail, sizeof(result->error_detail),
                     "Expected prev=%s", ctx->chain.rx.last_hash);
        }
        return err;
    }
    
    /* Step 5: Check payload size */
    size_t payload_len = strlen(outer.payload);
    if (payload_len > EWSP_MAX_PAYLOAD_SIZE * 2) {
        result->error = EWSP_ERR_PAYLOAD_TOO_LARGE;
        return EWSP_ERR_PAYLOAD_TOO_LARGE;
    }
    
    /* Step 6: Decrypt payload */
    uint8_t decrypted[EWSP_MAX_INNER_JSON];
    size_t decrypted_len;
    err = ewsp_crypto_decrypt(&ctx->crypto, outer.payload, 
                              decrypted, sizeof(decrypted) - 1, &decrypted_len);
    if (err != EWSP_OK) {
        result->error = EWSP_ERR_DECRYPT_FAILED;
        strcpy(result->error_detail, "Payload decryption failed");
        return EWSP_ERR_DECRYPT_FAILED;
    }
    decrypted[decrypted_len] = '\0';
    
    /* Step 7: Parse inner JSON */
    ewsp_json_reader_t r;
    ewsp_json_reader_init(&r, (const char*)decrypted, decrypted_len);
    
    /* Check if "cmd" field exists (requests have it, responses don't) */
    result->is_response = !ewsp_json_has_key(&r, "cmd");
    
    if (!result->is_response) {
        ewsp_json_get_string(&r, "cmd", result->command, sizeof(result->command));
    }
    
    /* Get request ID */
    ewsp_json_get_string(&r, "rid", result->request_id, sizeof(result->request_id));
    
    /* Get data field (or copy whole decrypted as data for responses) */
    err = ewsp_json_get_object(&r, "d", result->data_json, sizeof(result->data_json));
    if (err != EWSP_OK) {
        /* For responses, copy all inner JSON as data */
        strncpy(result->data_json, (const char*)decrypted, sizeof(result->data_json) - 1);
        result->data_json[sizeof(result->data_json) - 1] = '\0';
    }
    
    /* Step 8: Update chain state */
    result->sequence = outer.sequence;
    strcpy(result->prev_hash, outer.prev_hash);
    ewsp_chain_hash_packet(packet_json, result->packet_hash);
    
    ewsp_chain_update_rx(&ctx->chain, outer.sequence, result->packet_hash);
    
    result->error = EWSP_OK;
    return EWSP_OK;
}

/* ============================================================================
 * State Persistence
 * ============================================================================ */

void ewsp_packet_export_state(const ewsp_packet_ctx* ctx, 
                               ewsp_chain_snapshot_t* snapshot) {
    if (!ctx || !snapshot) return;
    ewsp_chain_export(&ctx->chain, snapshot);
}

void ewsp_packet_import_state(ewsp_packet_ctx* ctx,
                               const ewsp_chain_snapshot_t* snapshot) {
    if (!ctx || !snapshot) return;
    ewsp_chain_import(&ctx->chain, snapshot);
}
