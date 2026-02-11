#include "vhttp_fs_lock.h"

#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static StaticSemaphore_t g_fs_lock_buf;
static SemaphoreHandle_t g_fs_lock = NULL;

static void vhttp_fs_lock_init(void) {
    if (g_fs_lock) {
        return;
    }
    g_fs_lock = xSemaphoreCreateRecursiveMutexStatic(&g_fs_lock_buf);
}

void vhttp_fs_lock(void) {
    vhttp_fs_lock_init();
    if (g_fs_lock) {
        (void)xSemaphoreTakeRecursive(g_fs_lock, portMAX_DELAY);
    }
}

void vhttp_fs_unlock(void) {
    if (g_fs_lock) {
        (void)xSemaphoreGiveRecursive(g_fs_lock);
    }
}

#else

void vhttp_fs_lock(void) {
}

void vhttp_fs_unlock(void) {
}

#endif
