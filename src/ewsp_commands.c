/**
 * @file ewsp_commands.c
 * @brief EWSP Core Library - Command Helpers Implementation
 * 
 * @author deadboizxc
 * @version 1.0
 */

#include "ewsp_commands.h"
#include "ewsp_json.h"
#include "ewsp_crypto.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

/* ============================================================================
 * Command Type Mapping
 * ============================================================================ */

typedef struct {
    ewsp_cmd_type_t type;
    const char* name;
    bool requires_data;
} cmd_entry_t;

static const cmd_entry_t cmd_table[] = {
    {EWSP_CMD_TYPE_PING, EWSP_CMD_PING, false},
    {EWSP_CMD_TYPE_WAKE, EWSP_CMD_WAKE, true},
    {EWSP_CMD_TYPE_INFO, EWSP_CMD_INFO, false},
    {EWSP_CMD_TYPE_RESTART, EWSP_CMD_RESTART, false},
    {EWSP_CMD_TYPE_OTA_START, EWSP_CMD_OTA_START, false},
    {EWSP_CMD_TYPE_OPEN_SETUP, EWSP_CMD_OPEN_SETUP, false},
    {EWSP_CMD_TYPE_WEB_CONTROL, EWSP_CMD_WEB_CONTROL, true},
    {EWSP_CMD_TYPE_CLOUD_CONTROL, EWSP_CMD_CLOUD_CONTROL, true},
    {EWSP_CMD_TYPE_CRYPTO_INFO, EWSP_CMD_CRYPTO_INFO, false},
    {EWSP_CMD_TYPE_COUNTER_INFO, EWSP_CMD_COUNTER_INFO, false},
    {EWSP_CMD_TYPE_RESET_COUNTER, EWSP_CMD_RESET_COUNTER, false},
    {EWSP_CMD_TYPE_UPDATE_TOKEN, EWSP_CMD_UPDATE_TOKEN, true},
    {EWSP_CMD_TYPE_SET_CLOUD, EWSP_CMD_SET_CLOUD, true},
    {EWSP_CMD_TYPE_GET_CLOUD_CONFIG, EWSP_CMD_GET_CLOUD_CONFIG, false},
    {EWSP_CMD_TYPE_SET_WIFI, EWSP_CMD_SET_WIFI, true},
    {EWSP_CMD_TYPE_GET_CONFIG, EWSP_CMD_GET_CONFIG, false},
    {EWSP_CMD_TYPE_SET_DEVICE_ID, EWSP_CMD_SET_DEVICE_ID, true},
    {EWSP_CMD_TYPE_SET_WEB_AUTH, EWSP_CMD_SET_WEB_AUTH, true},
    {EWSP_CMD_TYPE_FACTORY_RESET, EWSP_CMD_FACTORY_RESET, false},
    {EWSP_CMD_TYPE_CHAIN_SYNC, EWSP_CMD_CHAIN_SYNC, true},
    {EWSP_CMD_TYPE_CHAIN_RESET, EWSP_CMD_CHAIN_RESET, false},
};

#define CMD_TABLE_SIZE (sizeof(cmd_table) / sizeof(cmd_table[0]))

ewsp_cmd_type_t ewsp_cmd_from_name(const char* name) {
    if (!name) return EWSP_CMD_TYPE_UNKNOWN;
    
    for (size_t i = 0; i < CMD_TABLE_SIZE; i++) {
        if (strcmp(cmd_table[i].name, name) == 0) {
            return cmd_table[i].type;
        }
    }
    
    return EWSP_CMD_TYPE_UNKNOWN;
}

const char* ewsp_cmd_to_name(ewsp_cmd_type_t type) {
    for (size_t i = 0; i < CMD_TABLE_SIZE; i++) {
        if (cmd_table[i].type == type) {
            return cmd_table[i].name;
        }
    }
    
    return NULL;
}

bool ewsp_cmd_requires_data(ewsp_cmd_type_t type) {
    for (size_t i = 0; i < CMD_TABLE_SIZE; i++) {
        if (cmd_table[i].type == type) {
            return cmd_table[i].requires_data;
        }
    }
    
    return false;
}

/* ============================================================================
 * Helper: Generate Request ID
 * ============================================================================ */

static void generate_rid(char rid[9]) {
    static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    uint8_t random_bytes[8];
    
    ewsp_random_bytes(random_bytes, 8);
    
    for (int i = 0; i < 8; i++) {
        rid[i] = chars[random_bytes[i] % (sizeof(chars) - 1)];
    }
    rid[8] = '\0';
}

/* ============================================================================
 * Command Builders
 * ============================================================================ */

ewsp_error_t ewsp_cmd_build(const char* cmd, 
                             const char* data_json,
                             const char* rid,
                             char* json_out, 
                             size_t json_size) {
    if (!cmd || !json_out || json_size == 0) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    ewsp_json_writer_t w;
    ewsp_json_writer_init(&w, json_out, json_size);
    
    ewsp_json_write_object_start(&w);
    ewsp_json_write_kv_string(&w, "cmd", cmd);
    
    ewsp_json_write_key(&w, "d");
    if (data_json && data_json[0] != '\0') {
        ewsp_json_write_raw(&w, data_json);
    } else {
        ewsp_json_write_raw(&w, "{}");
    }
    
    /* Request ID */
    char rid_buf[9];
    if (!rid) {
        generate_rid(rid_buf);
        rid = rid_buf;
    }
    ewsp_json_write_kv_string(&w, "rid", rid);
    
    ewsp_json_write_object_end(&w);
    ewsp_json_writer_finish(&w);
    
    return ewsp_json_writer_has_error(&w) ? EWSP_ERR_BUFFER_TOO_SMALL : EWSP_OK;
}

ewsp_error_t ewsp_cmd_build_ping(char* json_out, size_t json_size) {
    return ewsp_cmd_build(EWSP_CMD_PING, NULL, NULL, json_out, json_size);
}

ewsp_error_t ewsp_cmd_build_wake(const char* mac, char* json_out, size_t json_size) {
    if (!mac) return EWSP_ERR_INVALID_PARAMS;
    
    /* Build data JSON: {"mac":"AA:BB:CC:DD:EE:FF"} */
    char data[64];
    ewsp_json_writer_t w;
    ewsp_json_writer_init(&w, data, sizeof(data));
    
    ewsp_json_write_object_start(&w);
    ewsp_json_write_kv_string(&w, "mac", mac);
    ewsp_json_write_object_end(&w);
    ewsp_json_writer_finish(&w);
    
    return ewsp_cmd_build(EWSP_CMD_WAKE, data, NULL, json_out, json_size);
}

ewsp_error_t ewsp_cmd_build_info(char* json_out, size_t json_size) {
    return ewsp_cmd_build(EWSP_CMD_INFO, NULL, NULL, json_out, json_size);
}

ewsp_error_t ewsp_cmd_build_restart(char* json_out, size_t json_size) {
    return ewsp_cmd_build(EWSP_CMD_RESTART, NULL, NULL, json_out, json_size);
}

/* ============================================================================
 * Response Builders
 * ============================================================================ */

ewsp_error_t ewsp_response_build(const char* status,
                                  const char* data_json,
                                  const char* rid,
                                  char* json_out,
                                  size_t json_size) {
    if (!status || !json_out || json_size == 0) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    ewsp_json_writer_t w;
    ewsp_json_writer_init(&w, json_out, json_size);
    
    ewsp_json_write_object_start(&w);
    ewsp_json_write_kv_string(&w, "status", status);
    
    if (data_json && data_json[0] != '\0') {
        /* Merge data fields (simple approach - just add "d" key) */
        ewsp_json_write_key(&w, "d");
        ewsp_json_write_raw(&w, data_json);
    }
    
    if (rid) {
        ewsp_json_write_kv_string(&w, "rid", rid);
    }
    
    ewsp_json_write_object_end(&w);
    ewsp_json_writer_finish(&w);
    
    return ewsp_json_writer_has_error(&w) ? EWSP_ERR_BUFFER_TOO_SMALL : EWSP_OK;
}

ewsp_error_t ewsp_response_build_ok(const char* rid, char* json_out, size_t json_size) {
    return ewsp_response_build("ok", NULL, rid, json_out, json_size);
}

ewsp_error_t ewsp_response_build_pong(const char* rid, char* json_out, size_t json_size) {
    return ewsp_response_build("ok", "{\"pong\":true}", rid, json_out, json_size);
}

ewsp_error_t ewsp_response_build_error(ewsp_error_t err, 
                                        const char* detail,
                                        const char* rid,
                                        char* json_out, 
                                        size_t json_size) {
    if (!json_out || json_size == 0) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    ewsp_json_writer_t w;
    ewsp_json_writer_init(&w, json_out, json_size);
    
    ewsp_json_write_object_start(&w);
    ewsp_json_write_kv_string(&w, "status", "error");
    ewsp_json_write_kv_string(&w, "error", ewsp_error_code_str(err));
    ewsp_json_write_kv_string(&w, "message", ewsp_error_message(err));
    
    if (detail && detail[0] != '\0') {
        ewsp_json_write_kv_string(&w, "detail", detail);
    }
    
    if (rid) {
        ewsp_json_write_kv_string(&w, "rid", rid);
    }
    
    ewsp_json_write_object_end(&w);
    ewsp_json_writer_finish(&w);
    
    return ewsp_json_writer_has_error(&w) ? EWSP_ERR_BUFFER_TOO_SMALL : EWSP_OK;
}

ewsp_error_t ewsp_response_build_info(const ewsp_device_info_t* info,
                                       const char* rid,
                                       char* json_out,
                                       size_t json_size) {
    if (!info || !json_out || json_size == 0) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    ewsp_json_writer_t w;
    ewsp_json_writer_init(&w, json_out, json_size);
    
    ewsp_json_write_object_start(&w);
    ewsp_json_write_kv_string(&w, "status", "ok");
    
    ewsp_json_write_kv_string(&w, "device_id", info->device_id);
    ewsp_json_write_kv_string(&w, "firmware_version", info->firmware_version);
    ewsp_json_write_kv_string(&w, "protocol_version", info->protocol_version);
    ewsp_json_write_kv_string(&w, "ip", info->ip_address);
    ewsp_json_write_kv_string(&w, "mac", info->mac_address);
    ewsp_json_write_kv_uint(&w, "uptime", info->uptime_seconds);
    ewsp_json_write_kv_int(&w, "rssi", info->wifi_rssi);
    ewsp_json_write_kv_uint(&w, "free_heap", info->free_heap);
    ewsp_json_write_kv_uint(&w, "request_counter", info->request_counter);
    ewsp_json_write_kv_bool(&w, "cloud_connected", info->cloud_connected);
    ewsp_json_write_kv_bool(&w, "web_enabled", info->web_server_enabled);
    ewsp_json_write_kv_bool(&w, "ota_enabled", info->ota_enabled);
    
    if (rid) {
        ewsp_json_write_kv_string(&w, "rid", rid);
    }
    
    ewsp_json_write_object_end(&w);
    ewsp_json_writer_finish(&w);
    
    return ewsp_json_writer_has_error(&w) ? EWSP_ERR_BUFFER_TOO_SMALL : EWSP_OK;
}

/* ============================================================================
 * Response Parsers
 * ============================================================================ */

ewsp_error_t ewsp_response_parse(const char* json, ewsp_response_t* response) {
    if (!json || !response) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    ewsp_response_init(response);
    
    ewsp_json_reader_t r;
    ewsp_json_reader_init(&r, json, strlen(json));
    
    /* Parse status */
    char status[32] = {0};
    ewsp_json_get_string(&r, "status", status, sizeof(status));
    
    response->success = (strcmp(status, "ok") == 0);
    
    if (!response->success) {
        /* Parse error info */
        char error_code[64] = {0};
        ewsp_json_get_string(&r, "error", error_code, sizeof(error_code));
        response->error_code = ewsp_error_from_str(error_code);
        
        ewsp_json_get_string(&r, "message", response->error_message, sizeof(response->error_message));
    }
    
    /* Parse request ID */
    ewsp_json_get_string(&r, "rid", response->request_id, sizeof(response->request_id));
    
    /* Parse data if present */
    ewsp_error_t err = ewsp_json_get_object(&r, "d", response->data.json_raw, sizeof(response->data.json_raw));
    response->has_data = (err == EWSP_OK);
    
    return EWSP_OK;
}

ewsp_error_t ewsp_response_parse_info(const char* json, ewsp_device_info_t* info) {
    if (!json || !info) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    ewsp_device_info_init(info);
    
    ewsp_json_reader_t r;
    ewsp_json_reader_init(&r, json, strlen(json));
    
    ewsp_json_get_string(&r, "device_id", info->device_id, sizeof(info->device_id));
    ewsp_json_get_string(&r, "firmware_version", info->firmware_version, sizeof(info->firmware_version));
    ewsp_json_get_string(&r, "protocol_version", info->protocol_version, sizeof(info->protocol_version));
    ewsp_json_get_string(&r, "ip", info->ip_address, sizeof(info->ip_address));
    ewsp_json_get_string(&r, "mac", info->mac_address, sizeof(info->mac_address));
    
    uint64_t val;
    if (ewsp_json_get_uint(&r, "uptime", &val) == EWSP_OK) {
        info->uptime_seconds = (uint32_t)val;
    }
    
    int64_t rssi;
    if (ewsp_json_get_int(&r, "rssi", &rssi) == EWSP_OK) {
        info->wifi_rssi = (int8_t)rssi;
    }
    
    if (ewsp_json_get_uint(&r, "free_heap", &val) == EWSP_OK) {
        info->free_heap = (uint32_t)val;
    }
    
    ewsp_json_get_uint(&r, "request_counter", &info->request_counter);
    ewsp_json_get_bool(&r, "cloud_connected", &info->cloud_connected);
    ewsp_json_get_bool(&r, "web_enabled", &info->web_server_enabled);
    ewsp_json_get_bool(&r, "ota_enabled", &info->ota_enabled);
    
    return EWSP_OK;
}

/* ============================================================================
 * MAC Address Utilities
 * ============================================================================ */

bool ewsp_mac_validate(const char* mac) {
    if (!mac) return false;
    
    size_t len = strlen(mac);
    if (len != 17) return false;  /* XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX */
    
    for (int i = 0; i < 17; i++) {
        if (i == 2 || i == 5 || i == 8 || i == 11 || i == 14) {
            if (mac[i] != ':' && mac[i] != '-') return false;
        } else {
            if (!isxdigit((unsigned char)mac[i])) return false;
        }
    }
    
    return true;
}

ewsp_error_t ewsp_mac_normalize(const char* mac, char* normalized_out) {
    if (!mac || !normalized_out) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    if (!ewsp_mac_validate(mac)) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    /* Copy and convert to uppercase with colons */
    int out_pos = 0;
    for (int i = 0; i < 17; i++) {
        if (mac[i] == '-') {
            normalized_out[out_pos++] = ':';
        } else {
            normalized_out[out_pos++] = (char)toupper((unsigned char)mac[i]);
        }
    }
    normalized_out[17] = '\0';
    
    return EWSP_OK;
}

ewsp_error_t ewsp_mac_to_bytes(const char* mac, uint8_t bytes_out[6]) {
    if (!mac || !bytes_out) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    char normalized[18];
    ewsp_error_t err = ewsp_mac_normalize(mac, normalized);
    if (err != EWSP_OK) {
        return err;
    }
    
    /* Parse: XX:XX:XX:XX:XX:XX */
    unsigned int b[6];
    int parsed = sscanf(normalized, "%02X:%02X:%02X:%02X:%02X:%02X",
                        &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]);
    
    if (parsed != 6) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    for (int i = 0; i < 6; i++) {
        bytes_out[i] = (uint8_t)b[i];
    }
    
    return EWSP_OK;
}
