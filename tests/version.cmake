function(run_git)
	execute_process(
		COMMAND "${GIT_EXECUTABLE}" ${ARGN}
		WORKING_DIRECTORY "${repository_directory}"
		RESULT_VARIABLE git_result
		OUTPUT_QUIET
		ERROR_VARIABLE git_error)
	if(NOT git_result EQUAL 0)
		message(FATAL_ERROR "git ${ARGN} failed: ${git_error}")
	endif()
endfunction()

function(assert_suffix expected description)
	execute_process(
		COMMAND "${CMAKE_COMMAND}"
			"-DGIT_EXECUTABLE=${GIT_EXECUTABLE}"
			"-DOUTPUT_FILE=${output_file}"
			"-DSOURCE_DIRECTORY=${repository_directory}"
			-P "${VERSION_SCRIPT}"
		RESULT_VARIABLE version_result
		ERROR_VARIABLE version_error)
	if(NOT version_result EQUAL 0)
		message(FATAL_ERROR "version generation failed: ${version_error}")
	endif()
	file(READ "${output_file}" header_content)
	string(FIND "${header_content}" "#define MCRELAY_VERSION_SUFFIX\t\"${expected}\"" suffix_position)
	if(suffix_position EQUAL -1)
		message(FATAL_ERROR "${description}: expected suffix '${expected}' in:\n${header_content}")
	endif()
endfunction()

if(NOT GIT_EXECUTABLE)
	message(FATAL_ERROR "Git is required for the version test")
endif()

set(repository_directory "${TEST_DIRECTORY}/version-test-repository")
set(output_file "${TEST_DIRECTORY}/version-test.h")
file(REMOVE_RECURSE "${repository_directory}")
file(REMOVE "${output_file}")
file(MAKE_DIRECTORY "${repository_directory}")
run_git(init)
run_git(config commit.gpgsign false)
run_git(config user.email version-test@example.invalid)
run_git(config user.name "Version Test")
file(WRITE "${repository_directory}/tracked.txt" "initial\n")
run_git(add tracked.txt)
run_git(commit -m initial)
execute_process(
	COMMAND "${GIT_EXECUTABLE}" rev-parse --short HEAD
	WORKING_DIRECTORY "${repository_directory}"
	OUTPUT_VARIABLE commit_hash
	OUTPUT_STRIP_TRAILING_WHITESPACE)

assert_suffix("+${commit_hash}" "clean commit")
run_git(tag test-version)
assert_suffix("" "tagged commit")
file(APPEND "${repository_directory}/tracked.txt" "dirty\n")
assert_suffix("+${commit_hash}-dirty" "dirty tagged commit")
