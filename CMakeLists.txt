cmake_minimum_required(VERSION 3.0)
project(mcrelay${EXEC_SUFFIX}
	VERSION 1.2
	LANGUAGES C)
add_executable(mcrelay${EXEC_SUFFIX} src/basic.c src/config.c src/log.c src/main.c src/misc.c src/network.c src/proto_legacy.c src/proto_modern.c src/proto_proxy.c)
target_link_libraries(mcrelay${EXEC_SUFFIX} -lresolv -lcjson)
