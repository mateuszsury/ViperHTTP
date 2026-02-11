#include "vhttp_logger.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static volatile uint8_t g_vhttp_log_level = VHTTP_LOG_LEVEL_DEFAULT;

static int vhttp_ascii_tolower(int c) {
    if (c >= 'A' && c <= 'Z') {
        return c + ('a' - 'A');
    }
    return c;
}

static int vhttp_str_ieq_n(const char *a, size_t a_len, const char *b) {
    size_t b_len = strlen(b);
    if (a_len != b_len) {
        return 0;
    }
    for (size_t i = 0; i < a_len; ++i) {
        if (vhttp_ascii_tolower((unsigned char)a[i]) != vhttp_ascii_tolower((unsigned char)b[i])) {
            return 0;
        }
    }
    return 1;
}

static uint8_t vhttp_log_level_clamp(uint8_t level) {
    if (level > VHTTP_LOG_LEVEL_TRACE) {
        return VHTTP_LOG_LEVEL_TRACE;
    }
    return level;
}

void vhttp_log_set_level(uint8_t level) {
    g_vhttp_log_level = vhttp_log_level_clamp(level);
}

uint8_t vhttp_log_get_level(void) {
    return vhttp_log_level_clamp(g_vhttp_log_level);
}

const char *vhttp_log_level_name(uint8_t level) {
    switch (level) {
        case VHTTP_LOG_LEVEL_OFF: return "off";
        case VHTTP_LOG_LEVEL_ERROR: return "error";
        case VHTTP_LOG_LEVEL_WARN: return "warn";
        case VHTTP_LOG_LEVEL_INFO: return "info";
        case VHTTP_LOG_LEVEL_DEBUG: return "debug";
        case VHTTP_LOG_LEVEL_TRACE: return "trace";
        default: return "unknown";
    }
}

int vhttp_log_level_from_name(const char *name, size_t len, uint8_t *out_level) {
    if (!name || len == 0 || !out_level) {
        return -1;
    }
    if (vhttp_str_ieq_n(name, len, "off")) {
        *out_level = VHTTP_LOG_LEVEL_OFF;
        return 0;
    }
    if (vhttp_str_ieq_n(name, len, "error")) {
        *out_level = VHTTP_LOG_LEVEL_ERROR;
        return 0;
    }
    if (vhttp_str_ieq_n(name, len, "warn") || vhttp_str_ieq_n(name, len, "warning")) {
        *out_level = VHTTP_LOG_LEVEL_WARN;
        return 0;
    }
    if (vhttp_str_ieq_n(name, len, "info")) {
        *out_level = VHTTP_LOG_LEVEL_INFO;
        return 0;
    }
    if (vhttp_str_ieq_n(name, len, "debug")) {
        *out_level = VHTTP_LOG_LEVEL_DEBUG;
        return 0;
    }
    if (vhttp_str_ieq_n(name, len, "trace")) {
        *out_level = VHTTP_LOG_LEVEL_TRACE;
        return 0;
    }
    return -1;
}

int vhttp_log_enabled(uint8_t level) {
    uint8_t current = vhttp_log_get_level();
    if (current == VHTTP_LOG_LEVEL_OFF) {
        return 0;
    }
    if (level == VHTTP_LOG_LEVEL_OFF) {
        return 0;
    }
    return level <= current;
}

void vhttp_log_printf(uint8_t level, const char *fmt, ...) {
    if (!fmt || !vhttp_log_enabled(level)) {
        return;
    }

    va_list ap;
    va_start(ap, fmt);
    printf("[VHTTP][%s] ", vhttp_log_level_name(level));
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
}
