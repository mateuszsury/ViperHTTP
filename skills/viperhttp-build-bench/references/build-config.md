# Build Config Extract (ViperHTTP)

## ESP-IDF Integration
- Add C sources under user module CMake.
- Include core, protocols, optimization, middleware, ipc, micropython binding.

## MicroPython Binding Files (from plan)
- micropython/mod_viperhttp.c
- micropython/vhttp_mp_app.c
- micropython/vhttp_mp_depends.c
- micropython/vhttp_mp_exceptions.c

## Required sdkconfig Options (from plan)
- CONFIG_FREERTOS_UNICORE=n
- CONFIG_COMPILER_OPTIMIZATION_PERF=y
- CONFIG_ESPTOOLPY_FLASHMODE_QIO=y
- CONFIG_ESPTOOLPY_FLASHFREQ_80M=y

## lwIP Tuning
- CONFIG_LWIP_TCP_MSS=1460
- CONFIG_LWIP_TCP_SND_BUF_DEFAULT=5840
- CONFIG_LWIP_TCP_WND_DEFAULT=5840
- CONFIG_LWIP_TCP_RECVMBOX_SIZE=12
- CONFIG_LWIP_TCP_ACCEPTMBOX_SIZE=8
- CONFIG_LWIP_TCPIP_RECVMBOX_SIZE=32
- CONFIG_LWIP_SO_REUSE=y

## PSRAM (ESP32-S3 with PSRAM)
- CONFIG_ESP32S3_SPIRAM_SUPPORT=y
- CONFIG_SPIRAM_MODE_OCT=y
- CONFIG_SPIRAM_SPEED_80M=y
