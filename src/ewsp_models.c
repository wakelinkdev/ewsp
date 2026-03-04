/**
 * @file ewsp_models.c
 * @brief EWSP Core Library - Data Models Implementation
 * 
 * @author deadboizxc
 * @version 1.0
 */

#include "ewsp_models.h"
#include "ewsp_crypto.h"
#include <string.h>

/* ============================================================================
 * Device Info
 * ============================================================================ */

void ewsp_device_info_init(ewsp_device_info_t* info) {
    if (!info) return;
    
    memset(info, 0, sizeof(*info));
    strcpy(info->protocol_version, "1.0");
}

/* ============================================================================
 * Inner Packet
 * ============================================================================ */

void ewsp_inner_packet_init(ewsp_inner_packet_t* pkt) {
    if (!pkt) return;
    
    memset(pkt, 0, sizeof(*pkt));
}

void ewsp_inner_packet_set_command(ewsp_inner_packet_t* pkt, const char* cmd) {
    if (!pkt || !cmd) return;
    
    size_t len = strlen(cmd);
    if (len > EWSP_MAX_COMMAND_LEN) {
        len = EWSP_MAX_COMMAND_LEN;
    }
    
    memcpy(pkt->command, cmd, len);
    pkt->command[len] = '\0';
}

void ewsp_inner_packet_set_rid(ewsp_inner_packet_t* pkt, const char* rid) {
    if (!pkt) return;
    
    if (rid) {
        size_t len = strlen(rid);
        if (len > EWSP_REQUEST_ID_LEN) {
            len = EWSP_REQUEST_ID_LEN;
        }
        memcpy(pkt->request_id, rid, len);
        pkt->request_id[len] = '\0';
    } else {
        ewsp_inner_packet_generate_rid(pkt);
    }
}

void ewsp_inner_packet_generate_rid(ewsp_inner_packet_t* pkt) {
    if (!pkt) return;
    
    static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    uint8_t random_bytes[EWSP_REQUEST_ID_LEN];
    
    ewsp_random_bytes(random_bytes, EWSP_REQUEST_ID_LEN);
    
    for (int i = 0; i < EWSP_REQUEST_ID_LEN; i++) {
        pkt->request_id[i] = chars[random_bytes[i] % (sizeof(chars) - 1)];
    }
    pkt->request_id[EWSP_REQUEST_ID_LEN] = '\0';
}

/* ============================================================================
 * Outer Packet
 * ============================================================================ */

void ewsp_outer_packet_init(ewsp_outer_packet_t* pkt) {
    if (!pkt) return;
    
    memset(pkt, 0, sizeof(*pkt));
    strcpy(pkt->version, "1.0");
    strcpy(pkt->prev_hash, EWSP_GENESIS_HASH);
}

/* ============================================================================
 * Response
 * ============================================================================ */

void ewsp_response_init(ewsp_response_t* resp) {
    if (!resp) return;
    
    memset(resp, 0, sizeof(*resp));
    resp->error_code = EWSP_OK;
}

void ewsp_response_set_success(ewsp_response_t* resp, const char* rid) {
    if (!resp) return;
    
    resp->success = true;
    resp->error_code = EWSP_OK;
    resp->error_message[0] = '\0';
    
    if (rid) {
        size_t len = strlen(rid);
        if (len > EWSP_REQUEST_ID_LEN) {
            len = EWSP_REQUEST_ID_LEN;
        }
        memcpy(resp->request_id, rid, len);
        resp->request_id[len] = '\0';
    }
}

void ewsp_response_set_error(ewsp_response_t* resp, ewsp_error_t err, const char* msg) {
    if (!resp) return;
    
    resp->success = false;
    resp->error_code = err;
    
    if (msg) {
        size_t len = strlen(msg);
        if (len >= sizeof(resp->error_message)) {
            len = sizeof(resp->error_message) - 1;
        }
        memcpy(resp->error_message, msg, len);
        resp->error_message[len] = '\0';
    } else {
        /* Use default message */
        const char* default_msg = ewsp_error_message(err);
        size_t len = strlen(default_msg);
        if (len >= sizeof(resp->error_message)) {
            len = sizeof(resp->error_message) - 1;
        }
        memcpy(resp->error_message, default_msg, len);
        resp->error_message[len] = '\0';
    }
}

/* ============================================================================
 * Packet Result
 * ============================================================================ */

void ewsp_packet_result_init(ewsp_packet_result_t* result) {
    if (!result) return;
    
    memset(result, 0, sizeof(*result));
    result->error = EWSP_OK;
    strcpy(result->prev_hash, EWSP_GENESIS_HASH);
    strcpy(result->packet_hash, EWSP_GENESIS_HASH);
}
