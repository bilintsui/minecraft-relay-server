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
	string(REPLACE ";" " " args_desc "${ARGN}")
	assert_contains(
		"${CLI_STDERR}"
		"Try '${program_name} help' for more information."
		"${args_desc}: invalid command hint"
	)
endfunction()

function(expect_invalid_message expected_message description)
	run_cli(22 ${ARGN})
	assert_contains(
		"${CLI_STDERR}"
		"${expected_message}"
		"${description}"
	)
	assert_contains(
		"${CLI_STDERR}"
		"Try '${program_name} help' for more information."
		"${description} hint"
	)
endfunction()

function(expect_invalid_argument expected_token)
	run_cli(22 ${ARGN})
	string(REPLACE ";" " " args_desc "${ARGN}")
	assert_contains(
		"${CLI_STDERR}"
		"Error: Invalid argument \"${expected_token}\"."
		"${args_desc}: invalid argument message"
	)
	assert_contains(
		"${CLI_STDERR}"
		"Try '${program_name} help' for more information."
		"${args_desc}: invalid argument hint"
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
expect_invalid_argument("extra" help run extra)
expect_invalid_argument("extra" run extra)
expect_invalid_argument("--config=${missing_config}" run "--config=${missing_config}")
expect_invalid_argument("-c${missing_config}" run "-c${missing_config}")
expect_invalid_argument("extra" run --config "${missing_config}" extra)
expect_invalid_argument("extra" version extra)

expect_invalid_message("Error: Unknown help topic \"unknown\"." "unknown help topic" help unknown)
expect_invalid_message("Error: Unknown command \"--version\"." "unknown command --version" --version)
expect_invalid_message("Error: Unknown command \"-v\"." "unknown command -v" -v)
expect_invalid_message("Error: Unknown command \"reload\"." "unknown command reload" reload)
expect_invalid_message("Error: Unknown command \"${missing_config}\"." "unknown command path" "${missing_config}")
expect_invalid_message("Error: Option -c requires a value." "missing value -c" run -c)
expect_invalid_message("Error: Option --config requires a value." "missing value --config" run --config)
expect_invalid_argument("/etc/mcrelay/config.json" version /etc/mcrelay/config.json)
expect_invalid_argument("--verbose" run --verbose)

function(expect_empty_config flag)
	execute_process(
		COMMAND "${MCRELAY}" run ${flag} ""
		RESULT_VARIABLE result
		OUTPUT_VARIABLE output
		ERROR_VARIABLE stderr
		TIMEOUT 5
	)
	if(NOT "${result}" STREQUAL "22")
		message(FATAL_ERROR
			"empty config path (${flag}): expected exit 22, got ${result}\n"
			"stdout:\n${output}\n"
			"stderr:\n${stderr}"
		)
	endif()
	assert_contains(
		"${stderr}"
		"Error: Configuration file path cannot be empty."
		"empty config path (${flag}) message"
	)
	assert_contains(
		"${stderr}"
		"Try '${program_name} help' for more information."
		"empty config path (${flag}) hint"
	)
endfunction()

expect_empty_config(-c)
expect_empty_config(--config)
