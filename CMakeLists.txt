cmake_minimum_required(VERSION 3.10)
project(mcrelay${EXEC_SUFFIX}
	VERSION 1.2
	LANGUAGES C)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
add_executable(mcrelay${EXEC_SUFFIX}
	src/basic.c src/config.c src/dns.c src/listener.c src/log.c src/main.c src/connsetup.c src/network.c src/protocol/common.c src/protocol/handshake.c src/protocol/handshake_legacy.c src/protocol/proxy.c)
option(DEBUG_MODE "Allow FIFO as config input (debug)" OFF)
option(UBSAN_TEST "Build the undefined-behavior sanitizer test" OFF)
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

	add_executable(dns_records_test tests/dns_records.c src/dns.c)
	target_include_directories(dns_records_test PRIVATE src)
	target_compile_definitions(dns_records_test PRIVATE _GNU_SOURCE)
	target_link_libraries(dns_records_test -lresolv)
	set_target_properties(dns_records_test PROPERTIES
		LINK_FLAGS "-Wl,--wrap=__res_nclose -Wl,--wrap=__res_ninit -Wl,--wrap=res_nmkquery -Wl,--wrap=res_nquery -Wl,--wrap=res_nsearch -Wl,--wrap=res_nsend")
	add_test(NAME dns_records COMMAND dns_records_test)
	add_executable(dns_srv_records_test tests/dns_srv_records.c src/dns.c)
	target_include_directories(dns_srv_records_test PRIVATE src)
	target_compile_definitions(dns_srv_records_test PRIVATE _GNU_SOURCE)
	target_link_libraries(dns_srv_records_test -lresolv)
	set_target_properties(dns_srv_records_test PROPERTIES
		LINK_FLAGS "-Wl,--wrap=__res_nclose -Wl,--wrap=__res_ninit -Wl,--wrap=res_nmkquery -Wl,--wrap=res_nquery -Wl,--wrap=res_nsearch -Wl,--wrap=res_nsend")
	add_test(NAME dns_srv_records COMMAND dns_srv_records_test)

	add_test(
		NAME cli
		COMMAND ${CMAKE_COMMAND}
			"-DMCRELAY=$<TARGET_FILE:mcrelay${EXEC_SUFFIX}>"
			"-DTEST_DIRECTORY=${CMAKE_CURRENT_BINARY_DIR}"
			-P "${CMAKE_CURRENT_SOURCE_DIR}/tests/cli.cmake"
	)

	add_executable(network_resolve_test tests/network_resolve.c src/network.c)
	target_include_directories(network_resolve_test PRIVATE src)
	target_compile_definitions(network_resolve_test PRIVATE _GNU_SOURCE)
	target_link_libraries(network_resolve_test -lresolv)
	set_target_properties(network_resolve_test PROPERTIES LINK_FLAGS "-Wl,--wrap=gethostbyname2")
	add_test(NAME network_resolve COMMAND network_resolve_test)
	add_executable(network_resolve_system_test tests/network_resolve_system.c src/network.c)
	target_include_directories(network_resolve_system_test PRIVATE src)
	target_compile_definitions(network_resolve_system_test PRIVATE _GNU_SOURCE)
	target_link_libraries(network_resolve_system_test -lresolv)
	add_test(NAME network_resolve_system COMMAND network_resolve_system_test)

	add_executable(protocol_packets_test tests/protocol_packets.c src/basic.c src/protocol/common.c src/protocol/handshake.c src/protocol/handshake_legacy.c)
	target_compile_definitions(protocol_packets_test PRIVATE _GNU_SOURCE)
	target_link_libraries(protocol_packets_test -lcjson)
	add_test(NAME protocol_packets COMMAND protocol_packets_test "${CMAKE_CURRENT_SOURCE_DIR}/tests/rawpackets")
	if(UBSAN_TEST AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
		add_executable(dns_records_ubsan_test tests/dns_records.c src/dns.c)
		target_include_directories(dns_records_ubsan_test PRIVATE src)
		target_compile_definitions(dns_records_ubsan_test PRIVATE _GNU_SOURCE)
		target_compile_options(dns_records_ubsan_test PRIVATE -fsanitize=undefined -fno-sanitize-recover=all)
		target_link_libraries(dns_records_ubsan_test -fsanitize=undefined -fno-sanitize-recover=all -lresolv)
		set_target_properties(dns_records_ubsan_test PROPERTIES
			LINK_FLAGS "-Wl,--wrap=__res_nclose -Wl,--wrap=__res_ninit -Wl,--wrap=res_nmkquery -Wl,--wrap=res_nquery -Wl,--wrap=res_nsearch -Wl,--wrap=res_nsend")
		add_test(NAME dns_records_ubsan COMMAND dns_records_ubsan_test)
		set_tests_properties(dns_records_ubsan PROPERTIES ENVIRONMENT "UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1")
		add_executable(dns_srv_records_ubsan_test tests/dns_srv_records.c src/dns.c)
		target_include_directories(dns_srv_records_ubsan_test PRIVATE src)
		target_compile_definitions(dns_srv_records_ubsan_test PRIVATE _GNU_SOURCE)
		target_compile_options(dns_srv_records_ubsan_test PRIVATE -fsanitize=undefined -fno-sanitize-recover=all)
		target_link_libraries(dns_srv_records_ubsan_test -fsanitize=undefined -fno-sanitize-recover=all -lresolv)
		set_target_properties(dns_srv_records_ubsan_test PROPERTIES
			LINK_FLAGS "-Wl,--wrap=__res_nclose -Wl,--wrap=__res_ninit -Wl,--wrap=res_nmkquery -Wl,--wrap=res_nquery -Wl,--wrap=res_nsearch -Wl,--wrap=res_nsend")
		add_test(NAME dns_srv_records_ubsan COMMAND dns_srv_records_ubsan_test)
		set_tests_properties(dns_srv_records_ubsan PROPERTIES ENVIRONMENT "UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1")

		add_executable(network_resolve_ubsan_test tests/network_resolve.c src/network.c)
		target_include_directories(network_resolve_ubsan_test PRIVATE src)
		target_compile_definitions(network_resolve_ubsan_test PRIVATE _GNU_SOURCE)
		target_compile_options(network_resolve_ubsan_test PRIVATE -fsanitize=undefined -fno-sanitize-recover=all)
		target_link_libraries(network_resolve_ubsan_test -fsanitize=undefined -fno-sanitize-recover=all -lresolv)
		set_target_properties(network_resolve_ubsan_test PROPERTIES LINK_FLAGS "-Wl,--wrap=gethostbyname2")
		add_test(NAME network_resolve_ubsan COMMAND network_resolve_ubsan_test)
		set_tests_properties(network_resolve_ubsan PROPERTIES ENVIRONMENT "UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1")

		add_executable(protocol_packets_ubsan_test tests/protocol_packets.c src/basic.c src/protocol/common.c src/protocol/handshake.c src/protocol/handshake_legacy.c)
		target_compile_definitions(protocol_packets_ubsan_test PRIVATE _GNU_SOURCE)
		target_compile_options(protocol_packets_ubsan_test PRIVATE -fsanitize=undefined -fno-sanitize-recover=all)
		target_link_libraries(protocol_packets_ubsan_test -fsanitize=undefined -fno-sanitize-recover=all -lcjson)
		add_test(NAME protocol_packets_ubsan COMMAND protocol_packets_ubsan_test "${CMAKE_CURRENT_SOURCE_DIR}/tests/rawpackets")
		set_tests_properties(protocol_packets_ubsan PROPERTIES ENVIRONMENT "UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1")
	endif()

	add_executable(systemd_notify_test tests/systemd_notify.c)
	target_compile_definitions(systemd_notify_test PRIVATE _GNU_SOURCE)
	add_test(NAME systemd_notify COMMAND systemd_notify_test $<TARGET_FILE:mcrelay${EXEC_SUFFIX}>)

	add_executable(worker_lifecycle_test tests/worker_lifecycle.c)
	target_compile_definitions(worker_lifecycle_test PRIVATE _GNU_SOURCE)
	add_test(NAME worker_lifecycle COMMAND worker_lifecycle_test $<TARGET_FILE:mcrelay${EXEC_SUFFIX}>)

	add_executable(worker_protocol_test tests/worker_protocol.c)
	target_compile_definitions(worker_protocol_test PRIVATE _GNU_SOURCE)
	add_test(NAME worker_protocol COMMAND worker_protocol_test $<TARGET_FILE:mcrelay${EXEC_SUFFIX}> "${CMAKE_CURRENT_SOURCE_DIR}/tests/rawpackets")
endif()
