#include "vhttp_ratelimit.h"
#include "vhttp_config.h"

#include <string.h>
#include <sys/time.h>

typedef struct {
    uint32_t key;
    uint32_t tokens_q16;
    uint32_t last_ms;
    uint8_t used;
} vhttp_rl_entry_t;

static vhttp_ratelimit_config_t g_rl;
static vhttp_rl_entry_t g_entries[VHTTP_RL_MAX_ENTRIES];
static uint32_t g_capacity_q16 = 0;
static uint32_t g_refill_per_ms_q16 = 0;

static uint32_t rl_now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t ms = (uint64_t)tv.tv_sec * 1000u + (uint64_t)(tv.tv_usec / 1000u);
    return (uint32_t)ms;
}

void vhttp_ratelimit_reset(void) {
    memset(&g_rl, 0, sizeof(g_rl));
    memset(g_entries, 0, sizeof(g_entries));
    g_capacity_q16 = 0;
    g_refill_per_ms_q16 = 0;
}

void vhttp_ratelimit_configure(const vhttp_ratelimit_config_t *cfg) {
    if (!cfg) {
        vhttp_ratelimit_reset();
        return;
    }
    g_rl = *cfg;
    if (!g_rl.enabled || g_rl.rate_per_sec == 0 || g_rl.burst == 0) {
        vhttp_ratelimit_reset();
        return;
    }
    g_capacity_q16 = (g_rl.burst << 16);
    g_refill_per_ms_q16 = (uint32_t)(((uint64_t)g_rl.rate_per_sec << 16) / 1000u);
    if (g_refill_per_ms_q16 == 0) {
        g_refill_per_ms_q16 = 1;
    }
    memset(g_entries, 0, sizeof(g_entries));
}

int vhttp_ratelimit_enabled(void) {
    return g_rl.enabled ? 1 : 0;
}

static vhttp_rl_entry_t *rl_get_entry(uint32_t key, uint32_t now_ms) {
    int free_idx = -1;
    int oldest_idx = 0;
    uint32_t oldest_ms = 0xFFFFFFFFu;

    for (int i = 0; i < VHTTP_RL_MAX_ENTRIES; ++i) {
        vhttp_rl_entry_t *entry = &g_entries[i];
        if (!entry->used) {
            if (free_idx < 0) {
                free_idx = i;
            }
            continue;
        }
        if (entry->key == key) {
            return entry;
        }
        if (entry->last_ms < oldest_ms) {
            oldest_ms = entry->last_ms;
            oldest_idx = i;
        }
    }

    int idx = free_idx >= 0 ? free_idx : oldest_idx;
    vhttp_rl_entry_t *entry = &g_entries[idx];
    entry->used = 1;
    entry->key = key;
    entry->tokens_q16 = g_capacity_q16;
    entry->last_ms = now_ms;
    return entry;
}

int vhttp_ratelimit_check(uint32_t key, uint32_t *retry_after_ms) {
    if (!g_rl.enabled || g_capacity_q16 == 0 || g_refill_per_ms_q16 == 0) {
        return 1;
    }
    uint32_t now_ms = rl_now_ms();
    vhttp_rl_entry_t *entry = rl_get_entry(key, now_ms);
    if (!entry) {
        return 1;
    }

    uint32_t delta = now_ms - entry->last_ms;
    if (delta > 0) {
        uint64_t refill = (uint64_t)delta * (uint64_t)g_refill_per_ms_q16;
        uint64_t tokens = (uint64_t)entry->tokens_q16 + refill;
        if (tokens > g_capacity_q16) {
            tokens = g_capacity_q16;
        }
        entry->tokens_q16 = (uint32_t)tokens;
        entry->last_ms = now_ms;
    }

    const uint32_t cost = (1u << 16);
    if (entry->tokens_q16 >= cost) {
        entry->tokens_q16 -= cost;
        return 1;
    }

    if (retry_after_ms) {
        uint32_t needed = cost - entry->tokens_q16;
        uint32_t ms = 0;
        if (g_refill_per_ms_q16 > 0) {
            ms = (needed + g_refill_per_ms_q16 - 1) / g_refill_per_ms_q16;
        }
        *retry_after_ms = ms;
    }
    return 0;
}
