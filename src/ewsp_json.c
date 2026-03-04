/**
 * @file ewsp_json.c
 * @brief EWSP Core Library - Minimal JSON Parser/Builder Implementation
 * 
 * @author deadboizxc
 * @version 1.0
 */

#include "ewsp_json.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

/* ============================================================================
 * JSON Reader Implementation
 * ============================================================================ */

void ewsp_json_reader_init(ewsp_json_reader_t* r, const char* json, size_t len) {
    if (!r) return;
    
    r->json = json;
    r->len = len;
    r->pos = 0;
    r->depth = 0;
    r->error = EWSP_OK;
}

/* Skip whitespace */
static void skip_ws(ewsp_json_reader_t* r) {
    while (r->pos < r->len && isspace((unsigned char)r->json[r->pos])) {
        r->pos++;
    }
}

/* Find key in current object and position at value start */
static bool find_key(ewsp_json_reader_t* r, const char* key) {
    size_t saved_pos = r->pos;
    r->pos = 0;
    skip_ws(r);
    
    if (r->pos >= r->len || r->json[r->pos] != '{') {
        r->pos = saved_pos;
        return false;
    }
    r->pos++;  /* Skip '{' */
    
    size_t key_len = strlen(key);
    
    while (r->pos < r->len) {
        skip_ws(r);
        
        if (r->json[r->pos] == '}') {
            break;  /* End of object */
        }
        
        /* Expect string key */
        if (r->json[r->pos] != '"') {
            if (r->json[r->pos] == ',') {
                r->pos++;
                continue;
            }
            break;
        }
        r->pos++;  /* Skip opening quote */
        
        /* Check if this is the key we want */
        size_t key_start = r->pos;
        while (r->pos < r->len && r->json[r->pos] != '"') {
            if (r->json[r->pos] == '\\') r->pos++;
            r->pos++;
        }
        
        size_t found_key_len = r->pos - key_start;
        bool key_match = (found_key_len == key_len) && 
                         (strncmp(r->json + key_start, key, key_len) == 0);
        
        if (r->pos < r->len) r->pos++;  /* Skip closing quote */
        
        skip_ws(r);
        if (r->pos < r->len && r->json[r->pos] == ':') {
            r->pos++;  /* Skip ':' */
        }
        skip_ws(r);
        
        if (key_match) {
            return true;  /* Positioned at value start */
        }
        
        /* Skip value */
        int depth = 0;
        bool in_string = false;
        while (r->pos < r->len) {
            char c = r->json[r->pos];
            
            if (in_string) {
                if (c == '\\') {
                    r->pos++;
                } else if (c == '"') {
                    in_string = false;
                }
            } else {
                if (c == '"') {
                    in_string = true;
                } else if (c == '{' || c == '[') {
                    depth++;
                } else if (c == '}' || c == ']') {
                    if (depth == 0) break;
                    depth--;
                } else if (c == ',' && depth == 0) {
                    break;
                }
            }
            r->pos++;
        }
    }
    
    r->pos = saved_pos;
    return false;
}

ewsp_error_t ewsp_json_get_string(ewsp_json_reader_t* r, 
                                   const char* key,
                                   char* value_out, 
                                   size_t value_size) {
    if (!r || !key || !value_out || value_size == 0) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    size_t saved_pos = r->pos;
    
    if (!find_key(r, key)) {
        r->pos = saved_pos;
        return EWSP_ERR_MISSING_FIELD;
    }
    
    skip_ws(r);
    
    if (r->pos >= r->len || r->json[r->pos] != '"') {
        r->pos = saved_pos;
        return EWSP_ERR_INVALID_JSON;
    }
    r->pos++;  /* Skip opening quote */
    
    size_t out_pos = 0;
    while (r->pos < r->len && r->json[r->pos] != '"') {
        if (out_pos >= value_size - 1) {
            r->pos = saved_pos;
            return EWSP_ERR_BUFFER_TOO_SMALL;
        }
        
        if (r->json[r->pos] == '\\' && r->pos + 1 < r->len) {
            r->pos++;
            char c = r->json[r->pos];
            switch (c) {
                case 'n': value_out[out_pos++] = '\n'; break;
                case 'r': value_out[out_pos++] = '\r'; break;
                case 't': value_out[out_pos++] = '\t'; break;
                case '"': value_out[out_pos++] = '"'; break;
                case '\\': value_out[out_pos++] = '\\'; break;
                default: value_out[out_pos++] = c; break;
            }
        } else {
            value_out[out_pos++] = r->json[r->pos];
        }
        r->pos++;
    }
    
    value_out[out_pos] = '\0';
    r->pos = saved_pos;
    return EWSP_OK;
}

ewsp_error_t ewsp_json_get_int(ewsp_json_reader_t* r, 
                                const char* key,
                                int64_t* value_out) {
    if (!r || !key || !value_out) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    size_t saved_pos = r->pos;
    
    if (!find_key(r, key)) {
        r->pos = saved_pos;
        return EWSP_ERR_MISSING_FIELD;
    }
    
    skip_ws(r);
    
    char* end;
    *value_out = strtoll(r->json + r->pos, &end, 10);
    
    if (end == r->json + r->pos) {
        r->pos = saved_pos;
        return EWSP_ERR_INVALID_JSON;
    }
    
    r->pos = saved_pos;
    return EWSP_OK;
}

ewsp_error_t ewsp_json_get_uint(ewsp_json_reader_t* r,
                                 const char* key,
                                 uint64_t* value_out) {
    int64_t v;
    ewsp_error_t err = ewsp_json_get_int(r, key, &v);
    if (err == EWSP_OK) {
        *value_out = (uint64_t)v;
    }
    return err;
}

ewsp_error_t ewsp_json_get_bool(ewsp_json_reader_t* r,
                                 const char* key,
                                 bool* value_out) {
    if (!r || !key || !value_out) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    size_t saved_pos = r->pos;
    
    if (!find_key(r, key)) {
        r->pos = saved_pos;
        return EWSP_ERR_MISSING_FIELD;
    }
    
    skip_ws(r);
    
    if (r->pos + 4 <= r->len && strncmp(r->json + r->pos, "true", 4) == 0) {
        *value_out = true;
        r->pos = saved_pos;
        return EWSP_OK;
    }
    
    if (r->pos + 5 <= r->len && strncmp(r->json + r->pos, "false", 5) == 0) {
        *value_out = false;
        r->pos = saved_pos;
        return EWSP_OK;
    }
    
    r->pos = saved_pos;
    return EWSP_ERR_INVALID_JSON;
}

ewsp_error_t ewsp_json_get_object(ewsp_json_reader_t* r,
                                   const char* key,
                                   char* json_out,
                                   size_t json_size) {
    if (!r || !key || !json_out || json_size == 0) {
        return EWSP_ERR_INVALID_PARAMS;
    }
    
    size_t saved_pos = r->pos;
    
    if (!find_key(r, key)) {
        r->pos = saved_pos;
        return EWSP_ERR_MISSING_FIELD;
    }
    
    skip_ws(r);
    
    /* Find object/array bounds */
    size_t start = r->pos;
    int depth = 0;
    bool in_string = false;
    
    while (r->pos < r->len) {
        char c = r->json[r->pos];
        
        if (in_string) {
            if (c == '\\') {
                r->pos++;
            } else if (c == '"') {
                in_string = false;
            }
        } else {
            if (c == '"') {
                in_string = true;
            } else if (c == '{' || c == '[') {
                depth++;
            } else if (c == '}' || c == ']') {
                depth--;
                if (depth == 0) {
                    r->pos++;
                    break;
                }
            }
        }
        r->pos++;
    }
    
    size_t len = r->pos - start;
    if (len >= json_size) {
        r->pos = saved_pos;
        return EWSP_ERR_BUFFER_TOO_SMALL;
    }
    
    memcpy(json_out, r->json + start, len);
    json_out[len] = '\0';
    
    r->pos = saved_pos;
    return EWSP_OK;
}

bool ewsp_json_has_key(ewsp_json_reader_t* r, const char* key) {
    if (!r || !key) return false;
    
    size_t saved_pos = r->pos;
    bool found = find_key(r, key);
    r->pos = saved_pos;
    return found;
}

/* ============================================================================
 * JSON Writer Implementation
 * ============================================================================ */

void ewsp_json_writer_init(ewsp_json_writer_t* w, char* buffer, size_t size) {
    if (!w) return;
    
    w->buffer = buffer;
    w->size = size;
    w->pos = 0;
    w->depth = 0;
    w->need_comma = false;
    w->error = EWSP_OK;
    
    if (buffer && size > 0) {
        buffer[0] = '\0';
    }
}

static ewsp_error_t write_char(ewsp_json_writer_t* w, char c) {
    if (w->pos >= w->size - 1) {
        w->error = EWSP_ERR_BUFFER_TOO_SMALL;
        return w->error;
    }
    w->buffer[w->pos++] = c;
    w->buffer[w->pos] = '\0';
    return EWSP_OK;
}

static ewsp_error_t write_str(ewsp_json_writer_t* w, const char* str) {
    size_t len = strlen(str);
    if (w->pos + len >= w->size) {
        w->error = EWSP_ERR_BUFFER_TOO_SMALL;
        return w->error;
    }
    memcpy(w->buffer + w->pos, str, len);
    w->pos += len;
    w->buffer[w->pos] = '\0';
    return EWSP_OK;
}

static ewsp_error_t write_comma_if_needed(ewsp_json_writer_t* w) {
    if (w->need_comma) {
        return write_char(w, ',');
    }
    return EWSP_OK;
}

ewsp_error_t ewsp_json_write_object_start(ewsp_json_writer_t* w) {
    if (!w || w->error != EWSP_OK) return w ? w->error : EWSP_ERR_INVALID_PARAMS;
    
    write_comma_if_needed(w);
    w->need_comma = false;
    w->depth++;
    return write_char(w, '{');
}

ewsp_error_t ewsp_json_write_object_end(ewsp_json_writer_t* w) {
    if (!w || w->error != EWSP_OK) return w ? w->error : EWSP_ERR_INVALID_PARAMS;
    
    w->depth--;
    w->need_comma = true;
    return write_char(w, '}');
}

ewsp_error_t ewsp_json_write_array_start(ewsp_json_writer_t* w) {
    if (!w || w->error != EWSP_OK) return w ? w->error : EWSP_ERR_INVALID_PARAMS;
    
    write_comma_if_needed(w);
    w->need_comma = false;
    w->depth++;
    return write_char(w, '[');
}

ewsp_error_t ewsp_json_write_array_end(ewsp_json_writer_t* w) {
    if (!w || w->error != EWSP_OK) return w ? w->error : EWSP_ERR_INVALID_PARAMS;
    
    w->depth--;
    w->need_comma = true;
    return write_char(w, ']');
}

ewsp_error_t ewsp_json_write_key(ewsp_json_writer_t* w, const char* key) {
    if (!w || !key || w->error != EWSP_OK) {
        return w ? w->error : EWSP_ERR_INVALID_PARAMS;
    }
    
    write_comma_if_needed(w);
    w->need_comma = false;
    
    write_char(w, '"');
    write_str(w, key);
    write_char(w, '"');
    return write_char(w, ':');
}

ewsp_error_t ewsp_json_write_string(ewsp_json_writer_t* w, const char* value) {
    if (!w || !value || w->error != EWSP_OK) {
        return w ? w->error : EWSP_ERR_INVALID_PARAMS;
    }
    
    write_char(w, '"');
    
    /* Escape special characters */
    for (const char* p = value; *p; p++) {
        switch (*p) {
            case '"':  write_str(w, "\\\""); break;
            case '\\': write_str(w, "\\\\"); break;
            case '\n': write_str(w, "\\n"); break;
            case '\r': write_str(w, "\\r"); break;
            case '\t': write_str(w, "\\t"); break;
            default:
                if ((unsigned char)*p < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)*p);
                    write_str(w, buf);
                } else {
                    write_char(w, *p);
                }
        }
    }
    
    ewsp_error_t err = write_char(w, '"');
    w->need_comma = true;
    return err;
}

ewsp_error_t ewsp_json_write_int(ewsp_json_writer_t* w, int64_t value) {
    if (!w || w->error != EWSP_OK) return w ? w->error : EWSP_ERR_INVALID_PARAMS;
    
    char buf[32];
    snprintf(buf, sizeof(buf), "%lld", (long long)value);
    ewsp_error_t err = write_str(w, buf);
    w->need_comma = true;
    return err;
}

ewsp_error_t ewsp_json_write_uint(ewsp_json_writer_t* w, uint64_t value) {
    if (!w || w->error != EWSP_OK) return w ? w->error : EWSP_ERR_INVALID_PARAMS;
    
    char buf[32];
    snprintf(buf, sizeof(buf), "%llu", (unsigned long long)value);
    ewsp_error_t err = write_str(w, buf);
    w->need_comma = true;
    return err;
}

ewsp_error_t ewsp_json_write_bool(ewsp_json_writer_t* w, bool value) {
    if (!w || w->error != EWSP_OK) return w ? w->error : EWSP_ERR_INVALID_PARAMS;
    
    ewsp_error_t err = write_str(w, value ? "true" : "false");
    w->need_comma = true;
    return err;
}

ewsp_error_t ewsp_json_write_null(ewsp_json_writer_t* w) {
    if (!w || w->error != EWSP_OK) return w ? w->error : EWSP_ERR_INVALID_PARAMS;
    
    ewsp_error_t err = write_str(w, "null");
    w->need_comma = true;
    return err;
}

ewsp_error_t ewsp_json_write_raw(ewsp_json_writer_t* w, const char* raw) {
    if (!w || !raw || w->error != EWSP_OK) {
        return w ? w->error : EWSP_ERR_INVALID_PARAMS;
    }
    
    ewsp_error_t err = write_str(w, raw);
    w->need_comma = true;
    return err;
}

ewsp_error_t ewsp_json_write_kv_string(ewsp_json_writer_t* w, 
                                        const char* key, 
                                        const char* value) {
    ewsp_error_t err = ewsp_json_write_key(w, key);
    if (err != EWSP_OK) return err;
    return ewsp_json_write_string(w, value);
}

ewsp_error_t ewsp_json_write_kv_int(ewsp_json_writer_t* w,
                                     const char* key,
                                     int64_t value) {
    ewsp_error_t err = ewsp_json_write_key(w, key);
    if (err != EWSP_OK) return err;
    return ewsp_json_write_int(w, value);
}

ewsp_error_t ewsp_json_write_kv_uint(ewsp_json_writer_t* w,
                                      const char* key,
                                      uint64_t value) {
    ewsp_error_t err = ewsp_json_write_key(w, key);
    if (err != EWSP_OK) return err;
    return ewsp_json_write_uint(w, value);
}

ewsp_error_t ewsp_json_write_kv_bool(ewsp_json_writer_t* w,
                                      const char* key,
                                      bool value) {
    ewsp_error_t err = ewsp_json_write_key(w, key);
    if (err != EWSP_OK) return err;
    return ewsp_json_write_bool(w, value);
}

ewsp_error_t ewsp_json_write_kv_raw(ewsp_json_writer_t* w,
                                     const char* key,
                                     const char* raw_json) {
    ewsp_error_t err = ewsp_json_write_key(w, key);
    if (err != EWSP_OK) return err;
    return ewsp_json_write_raw(w, raw_json);
}

size_t ewsp_json_writer_finish(ewsp_json_writer_t* w) {
    if (!w) return 0;
    if (w->buffer && w->pos < w->size) {
        w->buffer[w->pos] = '\0';
    }
    return w->pos;
}

/* ============================================================================
 * String Escaping
 * ============================================================================ */

int ewsp_json_escape_string(const char* input, char* output, size_t output_size) {
    if (!input || !output || output_size == 0) {
        return -1;
    }
    
    size_t out_pos = 0;
    
    for (const char* p = input; *p; p++) {
        const char* esc = NULL;
        char esc_buf[8];
        
        switch (*p) {
            case '"':  esc = "\\\""; break;
            case '\\': esc = "\\\\"; break;
            case '\n': esc = "\\n"; break;
            case '\r': esc = "\\r"; break;
            case '\t': esc = "\\t"; break;
            default:
                if ((unsigned char)*p < 0x20) {
                    snprintf(esc_buf, sizeof(esc_buf), "\\u%04x", (unsigned char)*p);
                    esc = esc_buf;
                }
        }
        
        if (esc) {
            size_t esc_len = strlen(esc);
            if (out_pos + esc_len >= output_size) {
                return -1;
            }
            memcpy(output + out_pos, esc, esc_len);
            out_pos += esc_len;
        } else {
            if (out_pos >= output_size - 1) {
                return -1;
            }
            output[out_pos++] = *p;
        }
    }
    
    output[out_pos] = '\0';
    return (int)out_pos;
}

int ewsp_json_unescape_string(const char* input, size_t input_len, 
                               char* output, size_t output_size) {
    if (!input || !output || output_size == 0) {
        return -1;
    }
    
    size_t out_pos = 0;
    size_t in_pos = 0;
    
    while (in_pos < input_len) {
        if (out_pos >= output_size - 1) {
            return -1;
        }
        
        if (input[in_pos] == '\\' && in_pos + 1 < input_len) {
            in_pos++;
            switch (input[in_pos]) {
                case 'n':  output[out_pos++] = '\n'; break;
                case 'r':  output[out_pos++] = '\r'; break;
                case 't':  output[out_pos++] = '\t'; break;
                case '"':  output[out_pos++] = '"'; break;
                case '\\': output[out_pos++] = '\\'; break;
                case 'u':
                    /* Unicode escape \uXXXX - simple ASCII only for now */
                    if (in_pos + 4 < input_len) {
                        char hex[5] = {input[in_pos+1], input[in_pos+2], 
                                       input[in_pos+3], input[in_pos+4], 0};
                        unsigned int code = (unsigned int)strtoul(hex, NULL, 16);
                        if (code < 128) {
                            output[out_pos++] = (char)code;
                        }
                        in_pos += 4;
                    }
                    break;
                default:
                    output[out_pos++] = input[in_pos];
            }
        } else {
            output[out_pos++] = input[in_pos];
        }
        in_pos++;
    }
    
    output[out_pos] = '\0';
    return (int)out_pos;
}
