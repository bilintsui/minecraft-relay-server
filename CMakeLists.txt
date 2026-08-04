cmake_minimum_required(VERSION 3.10)
project(mcrelay${EXEC_SUFFIX}
	VERSION 1.2
	LANGUAGES C)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
add_executable(mcrelay${EXEC_SUFFIX}
	src/basic.c src/config.c src/log.c src/main.c src/connsetup.c src/network.c src/protocol/common.c src/protocol/handshake.c src/protocol/handshake_legacy.c src/protocol/proxy.c)
option(DEBUG_MODE "Allow FIFO as config input (debug)" OFF)
if(DEBUG_MODE)
	target_compile_definitions(mcrelay${EXEC_SUFFIX} PRIVATE _GNU_SOURCE DEBUG_MODE=true)
else()
	target_compile_definitions(mcrelay${EXEC_SUFFIX} PRIVATE _GNU_SOURCE DEBUG_MODE=false)
endif()
target_link_libraries(mcrelay${EXEC_SUFFIX} -lresolv -lcjson -lsystemd)

include(CTest)
if(BUILD_TESTING)
	add_executable(config_cache_test tests/config_cache.c src/basic.c src/config.c src/log.c)
	target_include_directories(config_cache_test PRIVATE src)
	target_compile_definitions(config_cache_test PRIVATE _GNU_SOURCE DEBUG_MODE=false)
	target_link_libraries(config_cache_test -lcjson)
	add_test(NAME config_cache COMMAND config_cache_test)

	add_test(
		NAME cli
		COMMAND ${CMAKE_COMMAND}
			"-DMCRELAY=$<TARGET_FILE:mcrelay${EXEC_SUFFIX}>"
			"-DTEST_DIRECTORY=${CMAKE_CURRENT_BINARY_DIR}"
			-P "${CMAKE_CURRENT_SOURCE_DIR}/tests/cli.cmake"
	)

	add_executable(protocol_packets_test tests/protocol_packets.c src/basic.c src/protocol/common.c src/protocol/handshake.c src/protocol/handshake_legacy.c)
	target_compile_definitions(protocol_packets_test PRIVATE _GNU_SOURCE)
	target_link_libraries(protocol_packets_test -lcjson)
	add_test(NAME protocol_packets COMMAND protocol_packets_test "${CMAKE_CURRENT_SOURCE_DIR}/tests/rawpackets")

	add_executable(systemd_notify_test tests/systemd_notify.c)
	target_compile_definitions(systemd_notify_test PRIVATE _GNU_SOURCE)
	add_test(NAME systemd_notify COMMAND systemd_notify_test $<TARGET_FILE:mcrelay${EXEC_SUFFIX}>)

	add_executable(worker_lifecycle_test tests/worker_lifecycle.c)
	target_compile_definitions(worker_lifecycle_test PRIVATE _GNU_SOURCE)
	add_test(NAME worker_lifecycle COMMAND worker_lifecycle_test $<TARGET_FILE:mcrelay${EXEC_SUFFIX}>)
endif()
