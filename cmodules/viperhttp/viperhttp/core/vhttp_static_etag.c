#include "vhttp_static_etag.h"

#include <string.h>

#include "vhttp_static_etag_table.h"

const vhttp_static_etag_entry_t *vhttp_static_etag_lookup(const char *path, size_t path_len) {
    if (!path || path_len == 0) {
        return NULL;
    }

    for (size_t i = 0; i < vhttp_static_etag_table_len; ++i) {
        const vhttp_static_etag_entry_t *entry = &vhttp_static_etag_table[i];
        if (entry->path_len != path_len) {
            continue;
        }
        if (memcmp(entry->path, path, path_len) == 0) {
            return entry;
        }
    }

    return NULL;
}
