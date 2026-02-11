#include "vhttp_static_fs.h"

// The static files are served from the MicroPython VFS (FAT) which is mounted
// by MicroPython at boot. No additional mount is required on the C side.
int vhttp_static_fs_mount(void) {
    return 0;
}

void vhttp_static_fs_unmount(void) {
}
