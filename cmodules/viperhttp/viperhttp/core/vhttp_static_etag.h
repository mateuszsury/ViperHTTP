#ifndef VHTTP_STATIC_ETAG_H
#define VHTTP_STATIC_ETAG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *path;
    uint16_t path_len;
    const char *etag;
    uint8_t etag_len;
} vhttp_static_etag_entry_t;

const vhttp_static_etag_entry_t *vhttp_static_etag_lookup(const char *path, size_t path_len);

#ifdef __cplusplus
}
#endif

#endif // VHTTP_STATIC_ETAG_H
