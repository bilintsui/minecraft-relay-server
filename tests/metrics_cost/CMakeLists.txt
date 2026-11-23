cmake_minimum_required(VERSION 3.12)
project(mcrelay_metrics_cost LANGUAGES C)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
get_filename_component(RELAY_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)

add_executable(snapshot_cost snapshot.c
	"${RELAY_ROOT}/src/basic.c" "${RELAY_ROOT}/src/listener_metrics.c" "${RELAY_ROOT}/src/log.c" "${RELAY_ROOT}/src/metrics.c" "${RELAY_ROOT}/src/timeutil.c"
	"${RELAY_ROOT}/src/resolver/cache.c" "${RELAY_ROOT}/src/resolver/dns.c" "${RELAY_ROOT}/src/resolver/helper.c" "${RELAY_ROOT}/src/resolver/ipc.c"
	"${RELAY_ROOT}/src/resolver/ipc_assembly.c" "${RELAY_ROOT}/src/resolver/supervisor.c" "${RELAY_ROOT}/src/resolver/util.c")
target_include_directories(snapshot_cost PRIVATE "${RELAY_ROOT}/src")
target_compile_definitions(snapshot_cost PRIVATE _GNU_SOURCE DEBUG_MODE=false)
target_link_libraries(snapshot_cost -lresolv -lcjson)

add_library(dns_redirect SHARED dns_redirect.c)
target_compile_definitions(dns_redirect PRIVATE _GNU_SOURCE)
target_link_libraries(dns_redirect -ldl)
