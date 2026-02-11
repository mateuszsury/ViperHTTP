#ifndef VHTTP_STATIC_H
#define VHTTP_STATIC_H

#include <stddef.h>
#include <stdint.h>

#include "vhttp_config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char prefix[VHTTP_STATIC_MAX_PREFIX];
    char root[VHTTP_STATIC_MAX_ROOT];
    uint16_t prefix_len;
    uint16_t root_len;
    uint8_t html;
} vhttp_static_mount_t;

typedef struct {
    char path[VHTTP_STATIC_MAX_PATH];
    size_t path_len;
    const char *content_type;
} vhttp_static_match_t;

void vhttp_static_reset(void);

// Returns:
//  0 on success
// -1 on invalid input / capacity
// -2 when prefix already mounted with a different root
int vhttp_static_mount(
    const char *prefix,
    size_t prefix_len,
    const char *root,
    size_t root_len,
    int html
);

// Mount an exact URL path to a single file in VFS.
// Returns:
//  0 on success
// -1 on invalid input / capacity
// -2 when path already mounted with a different file
// -3 when static filesystem mount failed
int vhttp_static_mount_file(
    const char *path,
    size_t path_len,
    const char *file,
    size_t file_len
);

// Resolve a URL path to a filesystem path if it matches a mount.
// Returns 1 if matched (out filled), 0 if no match or invalid path.
int vhttp_static_resolve(
    const char *path,
    size_t path_len,
    vhttp_static_match_t *out
);

#ifdef __cplusplus
}
#endif

#endif // VHTTP_STATIC_H
