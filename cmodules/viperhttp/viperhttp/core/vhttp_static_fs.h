#ifndef VHTTP_STATIC_FS_H
#define VHTTP_STATIC_FS_H

#ifdef __cplusplus
extern "C" {
#endif

// Static files are served from MicroPython VFS; mount is a no-op.
// Returns 0 on success.
int vhttp_static_fs_mount(void);

// Unmount the static filesystem (best-effort).
void vhttp_static_fs_unmount(void);

#ifdef __cplusplus
}
#endif

#endif // VHTTP_STATIC_FS_H
