#include "vhttp_static.h"
#include "vhttp_static_fs.h"

#include <string.h>

static vhttp_static_mount_t g_mounts[VHTTP_MAX_MOUNTS];
static uint8_t g_mount_count = 0;

typedef struct {
    char path[VHTTP_STATIC_MAX_PATH];
    char file[VHTTP_STATIC_MAX_PATH];
    uint16_t path_len;
    uint16_t file_len;
} vhttp_static_file_mount_t;

static vhttp_static_file_mount_t g_file_mounts[VHTTP_MAX_FILE_MOUNTS];
static uint8_t g_file_mount_count = 0;

void vhttp_static_reset(void) {
    g_mount_count = 0;
    g_file_mount_count = 0;
}

static size_t trim_trailing_slash(const char *ptr, size_t len) {
    while (len > 1 && ptr[len - 1] == '/') {
        len--;
    }
    return len;
}

static size_t normalize_root(const char *root, size_t root_len, char *out, size_t out_size) {
    const char *base = VHTTP_STATIC_FS_BASE;
    size_t base_len = strlen(base);

    if (base_len == 0 || (base_len == 1 && base[0] == '/')) {
        if (root_len >= out_size) {
            return 0;
        }
        memcpy(out, root, root_len);
        out[root_len] = '\0';
        return root_len;
    }

    while (base_len > 1 && base[base_len - 1] == '/') {
        base_len--;
    }

    if (root_len >= base_len && memcmp(root, base, base_len) == 0) {
        if (root_len >= out_size) {
            return 0;
        }
        memcpy(out, root, root_len);
        out[root_len] = '\0';
        return root_len;
    }

    if (root_len == 1 && root[0] == '/') {
        if (base_len >= out_size) {
            return 0;
        }
        memcpy(out, base, base_len);
        out[base_len] = '\0';
        return base_len;
    }

    if (base_len + root_len >= out_size) {
        return 0;
    }
    memcpy(out, base, base_len);
    memcpy(out + base_len, root, root_len);
    out[base_len + root_len] = '\0';
    return base_len + root_len;
}

static int has_backslash(const char *ptr, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (ptr[i] == '\\') {
            return 1;
        }
    }
    return 0;
}

static int has_dotdot_segment(const char *ptr, size_t len) {
    size_t i = 0;
    while (i < len) {
        while (i < len && ptr[i] == '/') {
            i++;
        }
        size_t seg_start = i;
        while (i < len && ptr[i] != '/') {
            i++;
        }
        size_t seg_len = i - seg_start;
        if (seg_len == 2 && ptr[seg_start] == '.' && ptr[seg_start + 1] == '.') {
            return 1;
        }
    }
    return 0;
}

static int ext_eq(const char *ext, size_t ext_len, const char *value) {
    size_t value_len = strlen(value);
    if (ext_len != value_len) {
        return 0;
    }
    for (size_t i = 0; i < ext_len; ++i) {
        char a = ext[i];
        char b = value[i];
        if (a >= 'A' && a <= 'Z') {
            a = (char)(a + ('a' - 'A'));
        }
        if (a != b) {
            return 0;
        }
    }
    return 1;
}

static const char *guess_content_type(const char *path, size_t len) {
    const char *dot = NULL;
    for (size_t i = 0; i < len; ++i) {
        if (path[i] == '/') {
            dot = NULL;
        } else if (path[i] == '.') {
            dot = path + i + 1;
        }
    }
    if (!dot) {
        return "application/octet-stream";
    }
    size_t ext_len = (size_t)((path + len) - dot);
    if (ext_eq(dot, ext_len, "html") || ext_eq(dot, ext_len, "htm")) {
        return "text/html; charset=utf-8";
    }
    if (ext_eq(dot, ext_len, "css")) {
        return "text/css; charset=utf-8";
    }
    if (ext_eq(dot, ext_len, "js")) {
        return "application/javascript";
    }
    if (ext_eq(dot, ext_len, "json")) {
        return "application/json";
    }
    if (ext_eq(dot, ext_len, "png")) {
        return "image/png";
    }
    if (ext_eq(dot, ext_len, "jpg") || ext_eq(dot, ext_len, "jpeg")) {
        return "image/jpeg";
    }
    if (ext_eq(dot, ext_len, "gif")) {
        return "image/gif";
    }
    if (ext_eq(dot, ext_len, "svg")) {
        return "image/svg+xml";
    }
    if (ext_eq(dot, ext_len, "ico")) {
        return "image/x-icon";
    }
    if (ext_eq(dot, ext_len, "txt")) {
        return "text/plain; charset=utf-8";
    }
    if (ext_eq(dot, ext_len, "wasm")) {
        return "application/wasm";
    }
    return "application/octet-stream";
}

int vhttp_static_mount(
    const char *prefix,
    size_t prefix_len,
    const char *root,
    size_t root_len,
    int html
) {
    if (!prefix || !root || prefix_len == 0 || root_len == 0) {
        return -1;
    }
    if (prefix[0] != '/' || root[0] != '/') {
        return -1;
    }

    if (vhttp_static_fs_mount() != 0) {
        return -3;
    }

    prefix_len = trim_trailing_slash(prefix, prefix_len);
    root_len = trim_trailing_slash(root, root_len);

    char normalized_root[VHTTP_STATIC_MAX_ROOT];
    size_t normalized_root_len = normalize_root(root, root_len, normalized_root, sizeof(normalized_root));
    if (normalized_root_len == 0) {
        return -1;
    }
    if (prefix_len >= VHTTP_STATIC_MAX_PREFIX || normalized_root_len >= VHTTP_STATIC_MAX_ROOT) {
        return -1;
    }

    for (uint8_t i = 0; i < g_mount_count; ++i) {
        vhttp_static_mount_t *mount = &g_mounts[i];
        if (mount->prefix_len == prefix_len &&
            memcmp(mount->prefix, prefix, prefix_len) == 0) {
            if (mount->root_len == normalized_root_len &&
                memcmp(mount->root, normalized_root, normalized_root_len) == 0) {
                mount->html = html ? 1 : 0;
                return 0;
            }
            return -2;
        }
    }

    if (g_mount_count >= VHTTP_MAX_MOUNTS) {
        return -1;
    }

    vhttp_static_mount_t *mount = &g_mounts[g_mount_count++];
    memcpy(mount->prefix, prefix, prefix_len);
    mount->prefix[prefix_len] = '\0';
    mount->prefix_len = (uint16_t)prefix_len;
    memcpy(mount->root, normalized_root, normalized_root_len);
    mount->root[normalized_root_len] = '\0';
    mount->root_len = (uint16_t)normalized_root_len;
    mount->html = html ? 1 : 0;

    return 0;
}

int vhttp_static_mount_file(
    const char *path,
    size_t path_len,
    const char *file,
    size_t file_len
) {
    if (!path || !file || path_len == 0 || file_len == 0) {
        return -1;
    }
    if (path[0] != '/' || file[0] != '/') {
        return -1;
    }

    if (vhttp_static_fs_mount() != 0) {
        return -3;
    }

    path_len = trim_trailing_slash(path, path_len);
    if (path_len >= VHTTP_STATIC_MAX_PATH) {
        return -1;
    }
    if (has_backslash(path, path_len) || has_dotdot_segment(path, path_len)) {
        return -1;
    }

    char normalized_file[VHTTP_STATIC_MAX_PATH];
    size_t normalized_file_len = normalize_root(file, file_len, normalized_file, sizeof(normalized_file));
    if (normalized_file_len == 0 || normalized_file_len >= VHTTP_STATIC_MAX_PATH) {
        return -1;
    }
    if (has_backslash(normalized_file, normalized_file_len) || has_dotdot_segment(normalized_file, normalized_file_len)) {
        return -1;
    }

    for (uint8_t i = 0; i < g_file_mount_count; ++i) {
        vhttp_static_file_mount_t *mount = &g_file_mounts[i];
        if (mount->path_len == path_len &&
            memcmp(mount->path, path, path_len) == 0) {
            if (mount->file_len == normalized_file_len &&
                memcmp(mount->file, normalized_file, normalized_file_len) == 0) {
                return 0;
            }
            return -2;
        }
    }

    if (g_file_mount_count >= VHTTP_MAX_FILE_MOUNTS) {
        return -1;
    }

    vhttp_static_file_mount_t *mount = &g_file_mounts[g_file_mount_count++];
    memcpy(mount->path, path, path_len);
    mount->path[path_len] = '\0';
    mount->path_len = (uint16_t)path_len;
    memcpy(mount->file, normalized_file, normalized_file_len);
    mount->file[normalized_file_len] = '\0';
    mount->file_len = (uint16_t)normalized_file_len;

    return 0;
}

int vhttp_static_resolve(
    const char *path,
    size_t path_len,
    vhttp_static_match_t *out
) {
    if (!path || !out || path_len == 0) {
        return 0;
    }

    for (uint8_t i = 0; i < g_file_mount_count; ++i) {
        const vhttp_static_file_mount_t *mount = &g_file_mounts[i];
        if (mount->path_len != path_len ||
            memcmp(path, mount->path, path_len) != 0) {
            continue;
        }
        memcpy(out->path, mount->file, mount->file_len);
        out->path[mount->file_len] = '\0';
        out->path_len = mount->file_len;
        out->content_type = guess_content_type(out->path, out->path_len);
        return 1;
    }

    for (uint8_t i = 0; i < g_mount_count; ++i) {
        const vhttp_static_mount_t *mount = &g_mounts[i];
        if (path_len < mount->prefix_len) {
            continue;
        }
        if (memcmp(path, mount->prefix, mount->prefix_len) != 0) {
            continue;
        }
        if (path_len > mount->prefix_len && path[mount->prefix_len] != '/') {
            continue;
        }

        const char *rel = NULL;
        size_t rel_len = 0;
        if (path_len == mount->prefix_len) {
            rel = "";
            rel_len = 0;
        } else {
            rel = path + mount->prefix_len;
            rel_len = path_len - mount->prefix_len;
        }

        if (rel_len > 0) {
            if (has_backslash(rel, rel_len) || has_dotdot_segment(rel, rel_len)) {
                return 0;
            }
        }

        int needs_index = 0;
        if (rel_len == 0 || (rel_len > 0 && rel[rel_len - 1] == '/')) {
            if (!mount->html) {
                return 0;
            }
            needs_index = 1;
        }

        size_t write = 0;
        if (mount->root_len + 1 >= VHTTP_STATIC_MAX_PATH) {
            return 0;
        }
        memcpy(out->path, mount->root, mount->root_len);
        write += mount->root_len;

        if (rel_len > 0) {
            if (write + rel_len >= VHTTP_STATIC_MAX_PATH) {
                return 0;
            }
            if (rel[0] == '/') {
                memcpy(out->path + write, rel, rel_len);
                write += rel_len;
            } else {
                out->path[write++] = '/';
                memcpy(out->path + write, rel, rel_len);
                write += rel_len;
            }
        } else if (needs_index) {
            const char *index_name = "/index.html";
            size_t index_len = strlen(index_name);
            if (write + index_len >= VHTTP_STATIC_MAX_PATH) {
                return 0;
            }
            memcpy(out->path + write, index_name, index_len);
            write += index_len;
        }

        if (needs_index && rel_len > 0) {
            const char *index_name = "index.html";
            size_t index_len = strlen(index_name);
            if (write + index_len >= VHTTP_STATIC_MAX_PATH) {
                return 0;
            }
            memcpy(out->path + write, index_name, index_len);
            write += index_len;
        }

        out->path[write] = '\0';
        out->path_len = write;
        out->content_type = guess_content_type(out->path, out->path_len);
        return 1;
    }

    return 0;
}
