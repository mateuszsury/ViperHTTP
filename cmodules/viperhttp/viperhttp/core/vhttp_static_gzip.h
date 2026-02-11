#ifndef VHTTP_STATIC_GZIP_H
#define VHTTP_STATIC_GZIP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t files_seen;
    uint32_t files_gzipped;
    uint32_t skipped_small;
    uint32_t skipped_existing;
    uint32_t skipped_ext;
    uint32_t errors;
} vhttp_gzip_stats_t;

int vhttp_static_gzip(
    const char *root,
    size_t root_len,
    size_t min_size,
    int level,
    vhttp_gzip_stats_t *stats
);

#ifdef __cplusplus
}
#endif

#endif // VHTTP_STATIC_GZIP_H
