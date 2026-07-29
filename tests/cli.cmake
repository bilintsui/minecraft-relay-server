if(NOT DEFINED MCRELAY OR "${MCRELAY}" STREQUAL "")
	message(FATAL_ERROR "MCRELAY is not set")
endif()
if(NOT EXISTS "${MCRELAY}")
	message(FATAL_ERROR "mcrelay executable not found: ${MCRELAY}")
endif()
if(NOT DEFINED TEST_DIRECTORY OR "${TEST_DIRECTORY}" STREQUAL "")
	message(FATAL_ERROR "TEST_DIRECTORY is not set")
endif()

get_filename_component(program_name "${MCRELAY}" NAME)

function(run_cli expected_result)
	execute_process(
		COMMAND "${MCRELAY}" ${ARGN}
		RESULT_VARIABLE result
		OUTPUT_VARIABLE output
		ERROR_VARIABLE error
		TIMEOUT 5
	)
	string(REPLACE ";" " " display_args "${ARGN}")
	if(NOT "${result}" STREQUAL "${expected_result}")
		message(FATAL_ERROR
			"${program_name} ${display_args}: expected exit ${expected_result}, got ${result}\n"
			"stdout:\n${output}\n"
			"stderr:\n${error}"
		)
	endif()
	set(CLI_STDOUT "${output}" PARENT_SCOPE)
	set(CLI_STDERR "${error}" PARENT_SCOPE)
endfunction()

function(assert_contains actual expected description)
	string(FIND "${actual}" "${expected}" position)
	if(position EQUAL -1)
		message(FATAL_ERROR
			"${description}: expected to find:\n${expected}\n"
			"actual output:\n${actual}"
		)
	endif()
endfunction()

function(assert_empty actual description)
	if(NOT "${actual}" STREQUAL "")
		message(FATAL_ERROR "${description}: expected empty output, got:\n${actual}")
	endif()
endfunction()

function(expect_invalid)
	run_cli(22 ${ARGN})
	assert_contains(
		"${CLI_STDERR}"
		"Try '${program_name} help' for more information."
		"invalid command hint"
	)
endfunction()

run_cli(0 help)
assert_empty("${CLI_STDERR}" "general help stderr")
assert_contains("${CLI_STDOUT}" "Minecraft Relay Server [Version " "general help banner")
assert_contains("${CLI_STDOUT}" "Usage: ${program_name} <command> ..." "general help usage")
assert_contains(
	"${CLI_STDOUT}"
	"Use \"${program_name} help <command>\" to get help for specific command."
	"general help hint"
)

run_cli(0 help run)
assert_empty("${CLI_STDERR}" "run help stderr")
assert_contains("${CLI_STDOUT}" "Usage: ${program_name} run [options]" "run help usage")
assert_contains("${CLI_STDOUT}" "-c, --config <config_file>" "run help option")
assert_contains("${CLI_STDOUT}" "Default: /etc/mcrelay/config.json" "run help default")

run_cli(0 help version)
assert_empty("${CLI_STDERR}" "version help stderr")
assert_contains("${CLI_STDOUT}" "Usage: ${program_name} version" "version help usage")

run_cli(0 help help)
assert_empty("${CLI_STDERR}" "help help stderr")
assert_contains("${CLI_STDOUT}" "Usage: ${program_name} help [<command>]" "help help usage")

run_cli(0 version)
assert_empty("${CLI_STDERR}" "version stderr")
assert_contains("${CLI_STDOUT}" "v" "version prefix")
assert_contains("${CLI_STDOUT}" "(" "version internal opening delimiter")
assert_contains("${CLI_STDOUT}" ")" "version internal closing delimiter")

string(RANDOM LENGTH 16 ALPHABET 0123456789abcdef random_suffix)
set(missing_config "${TEST_DIRECTORY}/mcrelay-cli-missing-${random_suffix}.json")
if(EXISTS "${missing_config}")
	message(FATAL_ERROR "generated missing config path exists: ${missing_config}")
endif()

run_cli(81 run -c "${missing_config}")
assert_contains("${CLI_STDOUT}${CLI_STDERR}" "${missing_config}" "short config option")

run_cli(81 run --config "${missing_config}")
assert_contains("${CLI_STDOUT}${CLI_STDERR}" "${missing_config}" "long config option")

if(NOT EXISTS "/etc/mcrelay/config.json")
	run_cli(81 run)
	assert_contains(
		"${CLI_STDOUT}${CLI_STDERR}"
		"/etc/mcrelay/config.json"
		"default config path"
	)
endif()

expect_invalid()
expect_invalid(help unknown)
expect_invalid(help run extra)
expect_invalid(--version)
expect_invalid(-v)
expect_invalid("${missing_config}")
expect_invalid(run extra)
expect_invalid(run "--config=${missing_config}")
expect_invalid(run "-c${missing_config}")
expect_invalid(run -c)
expect_invalid(run --config)
expect_invalid(run --config "${missing_config}" extra)
expect_invalid(version extra)

execute_process(
	COMMAND "${MCRELAY}" run -c ""
	RESULT_VARIABLE empty_config_result
	OUTPUT_VARIABLE empty_config_output
	ERROR_VARIABLE empty_config_error
	TIMEOUT 5
)
if(NOT "${empty_config_result}" STREQUAL "22")
	message(FATAL_ERROR
		"empty config path: expected exit 22, got ${empty_config_result}\n"
		"stdout:\n${empty_config_output}\n"
		"stderr:\n${empty_config_error}"
	)
endif()
assert_contains(
	"${empty_config_error}"
	"Try '${program_name} help' for more information."
	"empty config path hint"
)
