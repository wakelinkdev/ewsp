/**
 * @file ewsp_commands.h
 * @brief EWSP Core Library - Command Definitions
 * 
 * Unified command constants and serialization helpers.
 * Keeps command names in sync across all platforms.
 * 
 * @author deadboizxc
 * @version 1.0
 */

#ifndef EWSP_COMMANDS_H
#define EWSP_COMMANDS_H

#include "ewsp_types.h"
#include "ewsp_errors.h"
#include "ewsp_models.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Command Names (String Constants)
 * ============================================================================ */

/** Connection test command */
#define EWSP_CMD_PING           "ping"

/** Wake-on-LAN command */
#define EWSP_CMD_WAKE           "wake"

/** Device information command */
#define EWSP_CMD_INFO           "info"

/** Device restart command */
#define EWSP_CMD_RESTART        "restart"

/** Enable OTA update mode */
#define EWSP_CMD_OTA_START      "ota_start"

/** Enter setup/AP mode */
#define EWSP_CMD_OPEN_SETUP     "open_setup"

/** Web server control */
#define EWSP_CMD_WEB_CONTROL    "web_control"

/** Cloud connection control */
#define EWSP_CMD_CLOUD_CONTROL  "cloud_control"

/** Get crypto information */
#define EWSP_CMD_CRYPTO_INFO    "crypto_info"

/** Get counter information */
#define EWSP_CMD_COUNTER_INFO   "counter_info"

/** Reset request counter */
#define EWSP_CMD_RESET_COUNTER  "reset_counter"

/** Update device token */
#define EWSP_CMD_UPDATE_TOKEN   "update_token"

/** Configure cloud settings */
#define EWSP_CMD_SET_CLOUD      "set_cloud"

/** Get cloud configuration */
#define EWSP_CMD_GET_CLOUD_CONFIG "get_cloud_config"

/** Configure WiFi settings */
#define EWSP_CMD_SET_WIFI       "set_wifi"

/** Get device configuration */
#define EWSP_CMD_GET_CONFIG     "get_config"

/** Set device ID */
#define EWSP_CMD_SET_DEVICE_ID  "set_device_id"

/** Set web authentication */
#define EWSP_CMD_SET_WEB_AUTH   "set_web_auth"

/** Factory reset */
#define EWSP_CMD_FACTORY_RESET  "factory_reset"

/** Chain sync command */
#define EWSP_CMD_CHAIN_SYNC     "chain_sync"

/** Chain reset command */
#define EWSP_CMD_CHAIN_RESET    "chain_reset"

/* ============================================================================
 * Command Type Enumeration
 * ============================================================================ */

/**
 * @brief Command type enumeration.
 * 
 * Maps command names to enum values for switch statements.
 */
typedef enum {
    EWSP_CMD_TYPE_UNKNOWN = 0,
    EWSP_CMD_TYPE_PING,
    EWSP_CMD_TYPE_WAKE,
    EWSP_CMD_TYPE_INFO,
    EWSP_CMD_TYPE_RESTART,
    EWSP_CMD_TYPE_OTA_START,
    EWSP_CMD_TYPE_OPEN_SETUP,
    EWSP_CMD_TYPE_WEB_CONTROL,
    EWSP_CMD_TYPE_CLOUD_CONTROL,
    EWSP_CMD_TYPE_CRYPTO_INFO,
    EWSP_CMD_TYPE_COUNTER_INFO,
    EWSP_CMD_TYPE_RESET_COUNTER,
    EWSP_CMD_TYPE_UPDATE_TOKEN,
    EWSP_CMD_TYPE_SET_CLOUD,
    EWSP_CMD_TYPE_GET_CLOUD_CONFIG,
    EWSP_CMD_TYPE_SET_WIFI,
    EWSP_CMD_TYPE_GET_CONFIG,
    EWSP_CMD_TYPE_SET_DEVICE_ID,
    EWSP_CMD_TYPE_SET_WEB_AUTH,
    EWSP_CMD_TYPE_FACTORY_RESET,
    EWSP_CMD_TYPE_CHAIN_SYNC,
    EWSP_CMD_TYPE_CHAIN_RESET,
    EWSP_CMD_TYPE_COUNT  /* Number of command types */
} ewsp_cmd_type_t;

/**
 * @brief Get command type from command name.
 */
ewsp_cmd_type_t ewsp_cmd_from_name(const char* name);

/**
 * @brief Get command name from type.
 */
const char* ewsp_cmd_to_name(ewsp_cmd_type_t type);

/**
 * @brief Check if command requires data field.
 */
bool ewsp_cmd_requires_data(ewsp_cmd_type_t type);

/* ============================================================================
 * Command Builders (JSON Generation)
 * ============================================================================ */

/**
 * @brief Build ping command inner JSON.
 * 
 * Output: {"cmd":"ping","d":{},"rid":"XXXXXXXX"}
 */
ewsp_error_t ewsp_cmd_build_ping(char* json_out, size_t json_size);

/**
 * @brief Build wake command inner JSON.
 * 
 * Output: {"cmd":"wake","d":{"mac":"AA:BB:CC:DD:EE:FF"},"rid":"XXXXXXXX"}
 * 
 * @param mac MAC address string.
 * @param json_out Output buffer.
 * @param json_size Buffer size.
 */
ewsp_error_t ewsp_cmd_build_wake(const char* mac, char* json_out, size_t json_size);

/**
 * @brief Build info command inner JSON.
 */
ewsp_error_t ewsp_cmd_build_info(char* json_out, size_t json_size);

/**
 * @brief Build restart command inner JSON.
 */
ewsp_error_t ewsp_cmd_build_restart(char* json_out, size_t json_size);

/**
 * @brief Build generic command with data.
 * 
 * @param cmd Command name.
 * @param data_json Command data as JSON object string (e.g., "{\"key\":\"value\"}").
 * @param rid Request ID (NULL to auto-generate).
 * @param json_out Output buffer.
 * @param json_size Buffer size.
 */
ewsp_error_t ewsp_cmd_build(const char* cmd, 
                             const char* data_json,
                             const char* rid,
                             char* json_out, 
                             size_t json_size);

/* ============================================================================
 * Response Builders
 * ============================================================================ */

/**
 * @brief Build success response JSON.
 * 
 * Output: {"status":"ok","rid":"XXXXXXXX"}
 */
ewsp_error_t ewsp_response_build_ok(const char* rid, char* json_out, size_t json_size);

/**
 * @brief Build pong response JSON.
 * 
 * Output: {"status":"ok","pong":true,"rid":"XXXXXXXX"}
 */
ewsp_error_t ewsp_response_build_pong(const char* rid, char* json_out, size_t json_size);

/**
 * @brief Build error response JSON.
 * 
 * Output: {"status":"error","error":"ERROR_CODE","message":"...","rid":"..."}
 */
ewsp_error_t ewsp_response_build_error(ewsp_error_t err, 
                                        const char* detail,
                                        const char* rid,
                                        char* json_out, 
                                        size_t json_size);

/**
 * @brief Build device info response JSON.
 */
ewsp_error_t ewsp_response_build_info(const ewsp_device_info_t* info,
                                       const char* rid,
                                       char* json_out,
                                       size_t json_size);

/**
 * @brief Build generic response with data.
 */
ewsp_error_t ewsp_response_build(const char* status,
                                  const char* data_json,
                                  const char* rid,
                                  char* json_out,
                                  size_t json_size);

/* ============================================================================
 * Response Parsers
 * ============================================================================ */

/**
 * @brief Parse response JSON to structure.
 * 
 * @param json Input JSON string.
 * @param response Output response structure.
 * @return EWSP_OK on success.
 */
ewsp_error_t ewsp_response_parse(const char* json, ewsp_response_t* response);

/**
 * @brief Parse device info from JSON.
 */
ewsp_error_t ewsp_response_parse_info(const char* json, ewsp_device_info_t* info);

/* ============================================================================
 * MAC Address Utilities
 * ============================================================================ */

/**
 * @brief Validate MAC address format.
 * 
 * Accepts: AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF
 * 
 * @return true if valid format.
 */
bool ewsp_mac_validate(const char* mac);

/**
 * @brief Normalize MAC address to XX:XX:XX:XX:XX:XX format.
 */
ewsp_error_t ewsp_mac_normalize(const char* mac, char* normalized_out);

/**
 * @brief Parse MAC address to bytes.
 */
ewsp_error_t ewsp_mac_to_bytes(const char* mac, uint8_t bytes_out[6]);

#ifdef __cplusplus
}
#endif

#endif /* EWSP_COMMANDS_H */
