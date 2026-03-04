/**
 * @file ewsp.h
 * @brief EWSP Core Library - Master Header
 * 
 * Unified core library for WakeLink Protocol v1.0 (Blockchain).
 * Single codebase for all platforms: ESP8266/ESP32, Python, Android, iOS.
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * ARCHITECTURE
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                        EWSP Core Library (C)                       │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │  ewsp_crypto    │  ewsp_packet   │  ewsp_chain   │  ewsp_commands  │
 *   │  SHA256/HMAC    │  Serialize     │  Blockchain   │  Command types  │
 *   │  XChaCha20      │  Parse/Build   │  State mgmt   │  Serialization  │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │                      ewsp_types  │  ewsp_errors                    │
 *   │                      Base types  │  Error codes                    │
 *   └─────────────────────────────────────────────────────────────────────┘
 *                                  │
 *         ┌───────────────────────┼───────────────────────┐
 *         ▼                       ▼                       ▼
 *   ┌───────────┐           ┌───────────┐           ┌───────────┐
 *   │  Python   │           │  Android  │           │    iOS    │
 *   │  ctypes   │           │    JNI    │           │   Swift   │
 *   └───────────┘           └───────────┘           └───────────┘
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * USAGE
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * #include <ewsp.h>
 * 
 * // Initialize packet manager
 * ewsp_packet_ctx ctx;
 * ewsp_packet_init(&ctx, "device_token_32chars", "WL35080814");
 * 
 * // Create command packet (blockchain-linked)
 * char packet[2048];
 * ewsp_create_command_packet(&ctx, "wake", "{\"mac\":\"AA:BB:CC:DD:EE:FF\"}", packet);
 * 
 * // Process incoming packet
 * ewsp_packet_result result;
 * ewsp_process_packet(&ctx, incoming_json, &result);
 * 
 * @author deadboizxc
 * @version 1.0
 * @license NGC License v1.0
 */

#ifndef EWSP_H
#define EWSP_H

/* Version info */
#define EWSP_VERSION_MAJOR 1
#define EWSP_VERSION_MINOR 0
#define EWSP_VERSION_PATCH 0
#define EWSP_VERSION_STRING "1.0.0"
#define EWSP_PROTOCOL_VERSION "1.0"

/* Include all modules */
#include "ewsp_types.h"
#include "ewsp_errors.h"
#include "ewsp_crypto.h"
#include "ewsp_models.h"
#include "ewsp_chain.h"
#include "ewsp_packet.h"
#include "ewsp_commands.h"
#include "ewsp_json.h"
#include "ewsp_session.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Get EWSP library version string.
 * @return Version string "X.Y.Z"
 */
const char* ewsp_version(void);

/**
 * @brief Get protocol version string.
 * @return Protocol version "1.0"
 */
const char* ewsp_protocol_version(void);

/**
 * @brief Initialize library (call once at startup).
 * 
 * Performs any necessary global initialization.
 * Safe to call multiple times.
 * 
 * @return EWSP_OK on success, error code otherwise.
 */
ewsp_error_t ewsp_init(void);

/**
 * @brief Cleanup library resources (call on shutdown).
 */
void ewsp_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* EWSP_H */
