/**
 * @file ewsp_models.h
 * @brief EWSP Core Library - Data Models
 * 
 * Unified data structures for devices, commands, and responses.
 * Used across all platforms.
 * 
 * @author deadboizxc
 * @version 1.0
 */

#ifndef EWSP_MODELS_H
#define EWSP_MODELS_H

#include "ewsp_types.h"
#include "ewsp_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Device Information
 * ============================================================================ */

/**
 * @brief Device information structure.
 * 
 * Contains all device metadata returned by "info" command.
 */
typedef struct {
    char device_id[EWSP_MAX_DEVICE_ID_LEN + 1];  /**< Device identifier */
    char firmware_version[16];                   /**< Firmware version string */
    char protocol_version[8];                    /**< Protocol version "1.0" */
    char ip_address[16];                         /**< Device IP address */
    char mac_address[18];                        /**< WiFi MAC address */
    uint32_t uptime_seconds;                     /**< Uptime in seconds */
    int8_t wifi_rssi;                            /**< WiFi signal strength dBm */
    uint32_t free_heap;                          /**< Free heap memory bytes */
    uint64_t request_counter;                    /**< Total requests processed */
    bool cloud_connected;                        /**< Cloud connection status */
    bool web_server_enabled;                     /**< Web server status */
    bool ota_enabled;                            /**< OTA update enabled */
} ewsp_device_info_t;

/**
 * @brief Initialize device info to defaults.
 */
void ewsp_device_info_init(ewsp_device_info_t* info);

/* ============================================================================
 * Command Data Structures
 * ============================================================================ */

/**
 * @brief Wake command data.
 */
typedef struct {
    char mac[18];          /**< Target MAC address XX:XX:XX:XX:XX:XX */
    uint16_t port;         /**< WoL port (default 9) */
    char broadcast[16];    /**< Broadcast address (optional) */
} ewsp_wake_data_t;

/**
 * @brief WiFi configuration data.
 */
typedef struct {
    char ssid[33];         /**< WiFi SSID (max 32 chars) */
    char password[65];     /**< WiFi password (max 64 chars) */
} ewsp_wifi_config_t;

/**
 * @brief Cloud configuration data.
 */
typedef struct {
    char url[256];         /**< Cloud server URL */
    char api_token[128];   /**< API authentication token */
    bool enabled;          /**< Cloud connection enabled */
} ewsp_cloud_config_t;

/**
 * @brief Web authentication data.
 */
typedef struct {
    char username[33];     /**< Web UI username */
    char password[65];     /**< Web UI password */
} ewsp_web_auth_t;

/* ============================================================================
 * Inner Packet (Encrypted Content)
 * ============================================================================ */

/**
 * @brief Inner packet structure (v1.0 format).
 * 
 * This is what gets encrypted inside the payload.
 * JSON format: {"cmd":"...", "d":{...}, "rid":"..."}
 */
typedef struct {
    char command[EWSP_MAX_COMMAND_LEN + 1];      /**< Command name */
    char request_id[EWSP_REQUEST_ID_LEN + 1];    /**< 8-char request ID */
    
    /* Command-specific data union */
    union {
        ewsp_wake_data_t wake;
        ewsp_wifi_config_t wifi;
        ewsp_cloud_config_t cloud;
        ewsp_web_auth_t web_auth;
        char json_raw[EWSP_MAX_INNER_JSON];      /**< Raw JSON for complex data */
    } data;
    
    bool has_data;          /**< Whether data field is populated */
    bool use_raw_json;      /**< Use raw JSON instead of typed data */
} ewsp_inner_packet_t;

/**
 * @brief Initialize inner packet.
 */
void ewsp_inner_packet_init(ewsp_inner_packet_t* pkt);

/**
 * @brief Set command in inner packet.
 */
void ewsp_inner_packet_set_command(ewsp_inner_packet_t* pkt, const char* cmd);

/**
 * @brief Set request ID (or generate random).
 */
void ewsp_inner_packet_set_rid(ewsp_inner_packet_t* pkt, const char* rid);

/**
 * @brief Generate random request ID.
 */
void ewsp_inner_packet_generate_rid(ewsp_inner_packet_t* pkt);

/* ============================================================================
 * Outer Packet (Wire Format)
 * ============================================================================ */

/**
 * @brief Outer packet structure (v1.0 format).
 * 
 * JSON format:
 * {
 *   "v": "1.0",
 *   "id": "WL35080814",
 *   "seq": 42,
 *   "prev": "abc123...",
 *   "p": "encrypted_hex...",
 *   "sig": "hmac_hex..."
 * }
 */
typedef struct {
    char version[8];                                /**< Protocol version "1.0" */
    char device_id[EWSP_MAX_DEVICE_ID_LEN + 1];    /**< Device identifier */
    ewsp_seq_t sequence;                            /**< Sequence number */
    char prev_hash[EWSP_HASH_HEX_SIZE];            /**< Previous packet hash (64 hex) */
    char payload[EWSP_MAX_PAYLOAD_SIZE * 2 + 1];   /**< Encrypted payload (hex) */
    char signature[EWSP_HASH_HEX_SIZE];            /**< HMAC signature (64 hex) */
} ewsp_outer_packet_t;

/**
 * @brief Initialize outer packet.
 */
void ewsp_outer_packet_init(ewsp_outer_packet_t* pkt);

/* ============================================================================
 * Response Structures
 * ============================================================================ */

/**
 * @brief Generic response structure.
 * 
 * Used for command responses and status messages.
 */
typedef struct {
    bool success;                   /**< Operation successful */
    ewsp_error_t error_code;        /**< Error code if !success */
    char error_message[128];        /**< Error message if !success */
    char request_id[EWSP_REQUEST_ID_LEN + 1];  /**< Echoed request ID */
    
    /* Response data (depends on command) */
    union {
        ewsp_device_info_t device_info;     /**< For "info" command */
        char json_raw[EWSP_MAX_INNER_JSON]; /**< Raw JSON response */
        struct {
            char status[32];                /**< Status string (e.g., "enabled") */
        } simple;
    } data;
    
    bool has_data;
} ewsp_response_t;

/**
 * @brief Initialize response.
 */
void ewsp_response_init(ewsp_response_t* resp);

/**
 * @brief Set response as success.
 */
void ewsp_response_set_success(ewsp_response_t* resp, const char* rid);

/**
 * @brief Set response as error.
 */
void ewsp_response_set_error(ewsp_response_t* resp, ewsp_error_t err, const char* msg);

/* ============================================================================
 * Packet Processing Result
 * ============================================================================ */

/**
 * @brief Result of processing an incoming packet.
 */
typedef struct {
    ewsp_error_t error;                         /**< Error code (EWSP_OK if success) */
    char error_detail[256];                     /**< Error detail message */
    
    /* Parsed packet fields */
    ewsp_seq_t sequence;                        /**< Packet sequence number */
    char prev_hash[EWSP_HASH_HEX_SIZE];        /**< Previous hash from packet */
    char packet_hash[EWSP_HASH_HEX_SIZE];      /**< Hash of this packet */
    
    /* Decrypted inner content */
    char command[EWSP_MAX_COMMAND_LEN + 1];    /**< Command name (if present) */
    char request_id[EWSP_REQUEST_ID_LEN + 1];  /**< Request ID */
    char data_json[EWSP_MAX_INNER_JSON];       /**< Command data as JSON string */
    
    bool is_response;                           /**< True if this is a response (no cmd) */
} ewsp_packet_result_t;

/**
 * @brief Initialize packet result.
 */
void ewsp_packet_result_init(ewsp_packet_result_t* result);

#ifdef __cplusplus
}
#endif

#endif /* EWSP_MODELS_H */
