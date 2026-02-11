#ifndef VHTTP_TRUSTED_HOST_H
#define VHTTP_TRUSTED_HOST_H

#include <stddef.h>
#include <stdint.h>

#include "vhttp_config.h"
#include "vhttp_parser.h"

typedef struct {
    uint8_t enabled;
    uint8_t allow_any;
    uint8_t host_count;
    char hosts[VHTTP_TRUSTED_HOST_MAX][VHTTP_TRUSTED_HOST_MAX_LEN];
} vhttp_trusted_host_config_t;

void vhttp_trusted_host_reset(void);
void vhttp_trusted_host_defaults(vhttp_trusted_host_config_t *cfg);
void vhttp_trusted_host_configure(const vhttp_trusted_host_config_t *cfg);
int vhttp_trusted_host_enabled(void);
int vhttp_trusted_host_allowed(const vhttp_parsed_request_t *req);

#endif // VHTTP_TRUSTED_HOST_H
