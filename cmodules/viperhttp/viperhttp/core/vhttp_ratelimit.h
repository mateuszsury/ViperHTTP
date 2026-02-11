#ifndef VHTTP_RATELIMIT_H
#define VHTTP_RATELIMIT_H

#include <stdint.h>

typedef struct {
    uint8_t enabled;
    uint32_t rate_per_sec;
    uint32_t burst;
} vhttp_ratelimit_config_t;

void vhttp_ratelimit_reset(void);
void vhttp_ratelimit_configure(const vhttp_ratelimit_config_t *cfg);
int vhttp_ratelimit_enabled(void);
int vhttp_ratelimit_check(uint32_t key, uint32_t *retry_after_ms);

#endif // VHTTP_RATELIMIT_H
