/**
 * @file ewsp.c
 * @brief EWSP Core Library - Main Implementation
 * 
 * @author deadboizxc
 * @version 1.0
 */

#include "ewsp.h"

static bool ewsp_initialized = false;

const char* ewsp_version(void) {
    return EWSP_VERSION_STRING;
}

const char* ewsp_protocol_version(void) {
    return EWSP_PROTOCOL_VERSION;
}

ewsp_error_t ewsp_init(void) {
    if (ewsp_initialized) {
        return EWSP_OK;  /* Already initialized */
    }
    
    /* Any global initialization here */
    
    ewsp_initialized = true;
    return EWSP_OK;
}

void ewsp_cleanup(void) {
    if (!ewsp_initialized) {
        return;
    }
    
    /* Any global cleanup here */
    
    ewsp_initialized = false;
}
