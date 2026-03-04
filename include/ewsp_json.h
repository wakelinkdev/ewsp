/**
 * @file ewsp_json.h
 * @brief EWSP Core Library - Minimal JSON Parser/Builder
 * 
 * Lightweight JSON handling for embedded systems.
 * Optimized for EWSP packet format, not general-purpose.
 * 
 * Features:
 * - Zero heap allocation option
 * - Streaming parser for memory efficiency
 * - Simple builder for structured output
 * 
 * @author deadboizxc
 * @version 1.0
 */

#ifndef EWSP_JSON_H
#define EWSP_JSON_H

#include "ewsp_types.h"
#include "ewsp_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * JSON Value Types
 * ============================================================================ */

typedef enum {
    EWSP_JSON_NULL,
    EWSP_JSON_BOOL,
    EWSP_JSON_NUMBER,
    EWSP_JSON_STRING,
    EWSP_JSON_ARRAY,
    EWSP_JSON_OBJECT
} ewsp_json_type_t;

/* ============================================================================
 * JSON Reader (Parser)
 * ============================================================================ */

/**
 * @brief JSON reader context.
 */
typedef struct {
    const char* json;       /**< Input JSON string */
    size_t len;             /**< Total length */
    size_t pos;             /**< Current position */
    int depth;              /**< Nesting depth */
    ewsp_error_t error;     /**< Parse error */
} ewsp_json_reader_t;

/**
 * @brief Initialize JSON reader.
 */
void ewsp_json_reader_init(ewsp_json_reader_t* r, const char* json, size_t len);

/**
 * @brief Get string value by key from object.
 * 
 * @param r Reader (positioned at object start).
 * @param key Key to find.
 * @param value_out Output buffer for value.
 * @param value_size Buffer size.
 * @return EWSP_OK if found.
 */
ewsp_error_t ewsp_json_get_string(ewsp_json_reader_t* r, 
                                   const char* key,
                                   char* value_out, 
                                   size_t value_size);

/**
 * @brief Get integer value by key from object.
 */
ewsp_error_t ewsp_json_get_int(ewsp_json_reader_t* r, 
                                const char* key,
                                int64_t* value_out);

/**
 * @brief Get unsigned integer value by key.
 */
ewsp_error_t ewsp_json_get_uint(ewsp_json_reader_t* r,
                                 const char* key,
                                 uint64_t* value_out);

/**
 * @brief Get boolean value by key.
 */
ewsp_error_t ewsp_json_get_bool(ewsp_json_reader_t* r,
                                 const char* key,
                                 bool* value_out);

/**
 * @brief Get nested object as raw JSON string.
 */
ewsp_error_t ewsp_json_get_object(ewsp_json_reader_t* r,
                                   const char* key,
                                   char* json_out,
                                   size_t json_size);

/**
 * @brief Check if key exists in object.
 */
bool ewsp_json_has_key(ewsp_json_reader_t* r, const char* key);

/* ============================================================================
 * JSON Writer (Builder)
 * ============================================================================ */

/**
 * @brief JSON writer context.
 */
typedef struct {
    char* buffer;           /**< Output buffer */
    size_t size;            /**< Buffer size */
    size_t pos;             /**< Current position */
    int depth;              /**< Nesting depth */
    bool need_comma;        /**< Need comma before next item */
    ewsp_error_t error;     /**< Write error */
} ewsp_json_writer_t;

/**
 * @brief Initialize JSON writer.
 */
void ewsp_json_writer_init(ewsp_json_writer_t* w, char* buffer, size_t size);

/**
 * @brief Start object: {
 */
ewsp_error_t ewsp_json_write_object_start(ewsp_json_writer_t* w);

/**
 * @brief End object: }
 */
ewsp_error_t ewsp_json_write_object_end(ewsp_json_writer_t* w);

/**
 * @brief Start array: [
 */
ewsp_error_t ewsp_json_write_array_start(ewsp_json_writer_t* w);

/**
 * @brief End array: ]
 */
ewsp_error_t ewsp_json_write_array_end(ewsp_json_writer_t* w);

/**
 * @brief Write key for object field: "key":
 */
ewsp_error_t ewsp_json_write_key(ewsp_json_writer_t* w, const char* key);

/**
 * @brief Write string value: "value"
 */
ewsp_error_t ewsp_json_write_string(ewsp_json_writer_t* w, const char* value);

/**
 * @brief Write integer value.
 */
ewsp_error_t ewsp_json_write_int(ewsp_json_writer_t* w, int64_t value);

/**
 * @brief Write unsigned integer value.
 */
ewsp_error_t ewsp_json_write_uint(ewsp_json_writer_t* w, uint64_t value);

/**
 * @brief Write boolean value.
 */
ewsp_error_t ewsp_json_write_bool(ewsp_json_writer_t* w, bool value);

/**
 * @brief Write null value.
 */
ewsp_error_t ewsp_json_write_null(ewsp_json_writer_t* w);

/**
 * @brief Write raw JSON (no escaping).
 */
ewsp_error_t ewsp_json_write_raw(ewsp_json_writer_t* w, const char* raw);

/**
 * @brief Write key-value pair (string).
 * 
 * Shortcut for: write_key + write_string
 */
ewsp_error_t ewsp_json_write_kv_string(ewsp_json_writer_t* w, 
                                        const char* key, 
                                        const char* value);

/**
 * @brief Write key-value pair (integer).
 */
ewsp_error_t ewsp_json_write_kv_int(ewsp_json_writer_t* w,
                                     const char* key,
                                     int64_t value);

/**
 * @brief Write key-value pair (unsigned integer).
 */
ewsp_error_t ewsp_json_write_kv_uint(ewsp_json_writer_t* w,
                                      const char* key,
                                      uint64_t value);

/**
 * @brief Write key-value pair (boolean).
 */
ewsp_error_t ewsp_json_write_kv_bool(ewsp_json_writer_t* w,
                                      const char* key,
                                      bool value);

/**
 * @brief Write key with raw JSON value.
 */
ewsp_error_t ewsp_json_write_kv_raw(ewsp_json_writer_t* w,
                                     const char* key,
                                     const char* raw_json);

/**
 * @brief Finalize and null-terminate.
 * @return Length of JSON string (excluding null).
 */
size_t ewsp_json_writer_finish(ewsp_json_writer_t* w);

/**
 * @brief Get current length.
 */
static inline size_t ewsp_json_writer_len(const ewsp_json_writer_t* w) {
    return w->pos;
}

/**
 * @brief Check if writer has error.
 */
static inline bool ewsp_json_writer_has_error(const ewsp_json_writer_t* w) {
    return w->error != EWSP_OK;
}

/* ============================================================================
 * String Escaping
 * ============================================================================ */

/**
 * @brief Escape string for JSON.
 * 
 * Handles: \", \\, \n, \r, \t, etc.
 * 
 * @param input Input string.
 * @param output Output buffer.
 * @param output_size Buffer size.
 * @return Length of escaped string, or -1 on error.
 */
int ewsp_json_escape_string(const char* input, char* output, size_t output_size);

/**
 * @brief Unescape JSON string.
 * 
 * @param input Input (JSON escaped).
 * @param input_len Input length.
 * @param output Output buffer.
 * @param output_size Buffer size.
 * @return Length of unescaped string, or -1 on error.
 */
int ewsp_json_unescape_string(const char* input, size_t input_len, 
                               char* output, size_t output_size);

#ifdef __cplusplus
}
#endif

#endif /* EWSP_JSON_H */
