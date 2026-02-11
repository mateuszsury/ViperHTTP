# ViperHTTP user C module for MicroPython

set(USERMOD_DIR ${CMAKE_CURRENT_LIST_DIR})

add_library(usermod_viperhttp INTERFACE)

target_sources(usermod_viperhttp INTERFACE
    ${USERMOD_DIR}/viperhttp/mod_viperhttp.c
    ${USERMOD_DIR}/viperhttp/core/vhttp_parser.c
    ${USERMOD_DIR}/viperhttp/core/vhttp_router.c
    ${USERMOD_DIR}/viperhttp/core/vhttp_connection.c
    ${USERMOD_DIR}/viperhttp/core/vhttp_server.c
    ${USERMOD_DIR}/viperhttp/core/vhttp_server_task.c
    ${USERMOD_DIR}/viperhttp/core/vhttp_ipc.c
    ${USERMOD_DIR}/viperhttp/core/vhttp_logger.c
    ${USERMOD_DIR}/viperhttp/core/vhttp_static.c
    ${USERMOD_DIR}/viperhttp/core/vhttp_static_fs.c
    ${USERMOD_DIR}/viperhttp/core/vhttp_static_etag.c
    ${USERMOD_DIR}/viperhttp/core/vhttp_static_gzip.c
    ${USERMOD_DIR}/viperhttp/core/vhttp_fs_lock.c
    ${USERMOD_DIR}/viperhttp/core/vhttp_cors.c
    ${USERMOD_DIR}/viperhttp/core/vhttp_ratelimit.c
    ${USERMOD_DIR}/viperhttp/core/vhttp_trusted_host.c
)

target_compile_definitions(usermod_viperhttp INTERFACE
    VHTTP_ESP_PLATFORM=1
)

target_compile_options(usermod_viperhttp INTERFACE
    -mtext-section-literals
)

target_include_directories(usermod_viperhttp INTERFACE
    ${USERMOD_DIR}
    ${USERMOD_DIR}/viperhttp/core
)

target_link_libraries(usermod INTERFACE usermod_viperhttp)
