#include "vhttp_static_gzip.h"

#include "vhttp_config.h"
#include "vhttp_fs_lock.h"
#include "vhttp_static_fs.h"

#include <string.h>

#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "miniz.h"

#ifndef VHTTP_GZIP_MAX_DEPTH
#define VHTTP_GZIP_MAX_DEPTH 8
#endif

static int vhttp_path_has_suffix_ci(const char *path, size_t path_len, const char *suffix) {
    size_t suffix_len = strlen(suffix);
    if (path_len < suffix_len) {
        return 0;
    }
    const char *tail = path + (path_len - suffix_len);
    for (size_t i = 0; i < suffix_len; ++i) {
        char a = tail[i];
        char b = suffix[i];
        if (a >= 'A' && a <= 'Z') {
            a = (char)(a + ('a' - 'A'));
        }
        if (b >= 'A' && b <= 'Z') {
            b = (char)(b + ('a' - 'A'));
        }
        if (a != b) {
            return 0;
        }
    }
    return 1;
}

static int vhttp_is_compressible_ext(const char *path, size_t path_len) {
    static const char *k_exts[] = {
        ".html", ".htm", ".css", ".js", ".json", ".txt", ".svg", ".xml"
    };
    for (size_t i = 0; i < (sizeof(k_exts) / sizeof(k_exts[0])); ++i) {
        if (vhttp_path_has_suffix_ci(path, path_len, k_exts[i])) {
            return 1;
        }
    }
    return 0;
}

static int vhttp_map_level_to_probes(int level) {
    if (level <= 0) {
        return TDEFL_HUFFMAN_ONLY;
    }
    if (level <= 3) {
        return 32;
    }
    if (level <= 6) {
        return 128;
    }
    if (level <= 8) {
        return 512;
    }
    return 1024;
}

static int vhttp_gzip_file(const char *src, const char *dst, int level) {
    FILE *in = fopen(src, "rb");
    if (!in) {
        return -1;
    }
    FILE *out = fopen(dst, "wb");
    if (!out) {
        fclose(in);
        return -1;
    }

    tdefl_compressor *comp = (tdefl_compressor *)calloc(1, sizeof(tdefl_compressor));
    if (!comp) {
        fclose(in);
        fclose(out);
        unlink(dst);
        return -1;
    }

    int probes = vhttp_map_level_to_probes(level);
    int flags = probes & TDEFL_MAX_PROBES_MASK;

    if (tdefl_init(comp, NULL, NULL, flags) != TDEFL_STATUS_OKAY) {
        free(comp);
        fclose(in);
        fclose(out);
        unlink(dst);
        return -1;
    }

    uint8_t gzip_header[10] = {0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03};
    if (fwrite(gzip_header, 1, sizeof(gzip_header), out) != sizeof(gzip_header) || ferror(out)) {
        free(comp);
        fclose(in);
        fclose(out);
        unlink(dst);
        return -1;
    }

    uint8_t in_buf[2048];
    uint8_t out_buf[2048];
    mz_ulong crc = mz_crc32(0, NULL, 0);
    uint32_t isize = 0;

    for (;;) {
        size_t read_bytes = fread(in_buf, 1, sizeof(in_buf), in);
        if (read_bytes > 0) {
            crc = mz_crc32(crc, in_buf, read_bytes);
            isize += (uint32_t)read_bytes;
        }
        if (ferror(in)) {
            free(comp);
            fclose(in);
            fclose(out);
            unlink(dst);
            return -1;
        }

        int last = feof(in);
        size_t in_off = 0;
        tdefl_status status = TDEFL_STATUS_OKAY;

        do {
            size_t in_size = read_bytes - in_off;
            size_t out_size = sizeof(out_buf);
            tdefl_flush flush = last ? TDEFL_FINISH : TDEFL_NO_FLUSH;
            status = tdefl_compress(
                comp,
                (in_size > 0) ? (in_buf + in_off) : NULL,
                &in_size,
                out_buf,
                &out_size,
                flush
            );
            in_off += in_size;
            if (out_size > 0) {
                if (fwrite(out_buf, 1, out_size, out) != out_size || ferror(out)) {
                    free(comp);
                    fclose(in);
                    fclose(out);
                    unlink(dst);
                    return -1;
                }
            }
            if (status < 0) {
                free(comp);
                fclose(in);
                fclose(out);
                unlink(dst);
                return -1;
            }
        } while (in_off < read_bytes || (last && status == TDEFL_STATUS_OKAY));

        if (last) {
            if (status != TDEFL_STATUS_DONE) {
                free(comp);
                fclose(in);
                fclose(out);
                unlink(dst);
                return -1;
            }
            break;
        }
    }

    uint8_t trailer[8];
    trailer[0] = (uint8_t)(crc & 0xFF);
    trailer[1] = (uint8_t)((crc >> 8) & 0xFF);
    trailer[2] = (uint8_t)((crc >> 16) & 0xFF);
    trailer[3] = (uint8_t)((crc >> 24) & 0xFF);
    trailer[4] = (uint8_t)(isize & 0xFF);
    trailer[5] = (uint8_t)((isize >> 8) & 0xFF);
    trailer[6] = (uint8_t)((isize >> 16) & 0xFF);
    trailer[7] = (uint8_t)((isize >> 24) & 0xFF);

    if (fwrite(trailer, 1, sizeof(trailer), out) != sizeof(trailer) || ferror(out)) {
        free(comp);
        fclose(in);
        fclose(out);
        unlink(dst);
        return -1;
    }

    free(comp);
    fclose(in);
    fclose(out);
    return 0;
}

static int vhttp_gzip_walk(
    const char *dir,
    size_t dir_len,
    size_t min_size,
    int level,
    vhttp_gzip_stats_t *stats,
    int depth
) {
    if (depth > VHTTP_GZIP_MAX_DEPTH) {
        if (stats) {
            stats->errors++;
        }
        return -1;
    }

    DIR *dp = opendir(dir);
    if (!dp) {
        if (stats) {
            stats->errors++;
        }
        return -1;
    }

    struct dirent *entry;
    char path[VHTTP_STATIC_MAX_PATH];
    char gz_path[VHTTP_STATIC_MAX_PATH];
    char tmp_path[VHTTP_STATIC_MAX_PATH];

    while ((entry = readdir(dp)) != NULL) {
        const char *name = entry->d_name;
        if (!name || name[0] == '\0') {
            continue;
        }
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
            continue;
        }

        int plen = snprintf(path, sizeof(path), "%.*s/%s", (int)dir_len, dir, name);
        if (plen <= 0 || (size_t)plen >= sizeof(path)) {
            if (stats) {
                stats->errors++;
            }
            continue;
        }

        struct stat st;
        if (stat(path, &st) != 0) {
            if (stats) {
                stats->errors++;
            }
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            vhttp_gzip_walk(path, (size_t)plen, min_size, level, stats, depth + 1);
            continue;
        }

        if (!S_ISREG(st.st_mode)) {
            continue;
        }

        if (stats) {
            stats->files_seen++;
        }

        if (vhttp_path_has_suffix_ci(path, (size_t)plen, ".gz")) {
            if (stats) {
                stats->skipped_ext++;
            }
            continue;
        }

        if (!vhttp_is_compressible_ext(path, (size_t)plen)) {
            if (stats) {
                stats->skipped_ext++;
            }
            continue;
        }

        if (min_size > 0 && (size_t)st.st_size < min_size) {
            if (stats) {
                stats->skipped_small++;
            }
            continue;
        }

        int gz_len = snprintf(gz_path, sizeof(gz_path), "%s.gz", path);
        if (gz_len <= 0 || (size_t)gz_len >= sizeof(gz_path)) {
            if (stats) {
                stats->errors++;
            }
            continue;
        }

        struct stat gz_st;
        if (stat(gz_path, &gz_st) == 0) {
            if (gz_st.st_size > 0 && gz_st.st_mtime >= st.st_mtime) {
                if (stats) {
                    stats->skipped_existing++;
                }
                continue;
            }
        }

        int tmp_len = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", gz_path);
        if (tmp_len <= 0 || (size_t)tmp_len >= sizeof(tmp_path)) {
            if (stats) {
                stats->errors++;
            }
            continue;
        }

        if (vhttp_gzip_file(path, tmp_path, level) != 0) {
            unlink(tmp_path);
            if (stats) {
                stats->errors++;
            }
            continue;
        }

        if (rename(tmp_path, gz_path) != 0) {
            unlink(tmp_path);
            if (stats) {
                stats->errors++;
            }
            continue;
        }

        if (stats) {
            stats->files_gzipped++;
        }
    }

    closedir(dp);
    return 0;
}

int vhttp_static_gzip(
    const char *root,
    size_t root_len,
    size_t min_size,
    int level,
    vhttp_gzip_stats_t *stats
) {
    if (!root || root_len == 0) {
        return -1;
    }
    if (level < 0 || level > 9) {
        return -1;
    }

    if (stats) {
        memset(stats, 0, sizeof(*stats));
    }

    if (root_len >= VHTTP_STATIC_MAX_PATH) {
        if (stats) {
            stats->errors++;
        }
        return -1;
    }

    char root_buf[VHTTP_STATIC_MAX_PATH];
    memcpy(root_buf, root, root_len);
    root_buf[root_len] = '\0';
    const char *root_path = root_buf;
    size_t root_path_len = root_len;

    vhttp_fs_lock();

    size_t base_len = strlen(VHTTP_STATIC_FS_BASE);
    if (root_path_len >= base_len && memcmp(root_path, VHTTP_STATIC_FS_BASE, base_len) == 0) {
        if (vhttp_static_fs_mount() != 0) {
            if (stats) {
                stats->errors++;
            }
            vhttp_fs_unlock();
            return -2;
        }
    }

    int rc = vhttp_gzip_walk(root_path, root_path_len, min_size, level, stats, 0);
    vhttp_fs_unlock();
    return rc;
}

#else

int vhttp_static_gzip(
    const char *root,
    size_t root_len,
    size_t min_size,
    int level,
    vhttp_gzip_stats_t *stats
) {
    (void)root;
    (void)root_len;
    (void)min_size;
    (void)level;
    if (stats) {
        memset(stats, 0, sizeof(*stats));
        stats->errors = 1;
    }
    return -1;
}

#endif
