#ifndef VHTTP_LOGGER_H
#define VHTTP_LOGGER_H

#include <stddef.h>
#include <stdint.h>

#include "vhttp_config.h"

#ifdef __cplusplus
extern "C" {
#endif

void vhttp_log_set_level(uint8_t level);
uint8_t vhttp_log_get_level(void);
const char *vhttp_log_level_name(uint8_t level);
int vhttp_log_level_from_name(const char *name, size_t len, uint8_t *out_level);
int vhttp_log_enabled(uint8_t level);
void vhttp_log_printf(uint8_t level, const char *fmt, ...);

#define VHTTP_LOGE(...) do { if (vhttp_log_enabled(VHTTP_LOG_LEVEL_ERROR)) { vhttp_log_printf(VHTTP_LOG_LEVEL_ERROR, __VA_ARGS__); } } while (0)
#define VHTTP_LOGW(...) do { if (vhttp_log_enabled(VHTTP_LOG_LEVEL_WARN)) { vhttp_log_printf(VHTTP_LOG_LEVEL_WARN, __VA_ARGS__); } } while (0)
#define VHTTP_LOGI(...) do { if (vhttp_log_enabled(VHTTP_LOG_LEVEL_INFO)) { vhttp_log_printf(VHTTP_LOG_LEVEL_INFO, __VA_ARGS__); } } while (0)
#define VHTTP_LOGD(...) do { if (vhttp_log_enabled(VHTTP_LOG_LEVEL_DEBUG)) { vhttp_log_printf(VHTTP_LOG_LEVEL_DEBUG, __VA_ARGS__); } } while (0)
#define VHTTP_LOGT(...) do { if (vhttp_log_enabled(VHTTP_LOG_LEVEL_TRACE)) { vhttp_log_printf(VHTTP_LOG_LEVEL_TRACE, __VA_ARGS__); } } while (0)

#ifdef __cplusplus
}
#endif

#endif // VHTTP_LOGGER_H
