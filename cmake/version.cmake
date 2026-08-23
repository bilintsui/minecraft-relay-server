if(NOT DEFINED OUTPUT_FILE)
	message(FATAL_ERROR "OUTPUT_FILE is required")
endif()
if(NOT DEFINED SOURCE_DIRECTORY)
	message(FATAL_ERROR "SOURCE_DIRECTORY is required")
endif()

set(version_suffix "")
if(GIT_EXECUTABLE)
	execute_process(
		COMMAND "${GIT_EXECUTABLE}" rev-parse --is-inside-work-tree
		WORKING_DIRECTORY "${SOURCE_DIRECTORY}"
		RESULT_VARIABLE repository_result
		OUTPUT_VARIABLE repository_output
		OUTPUT_STRIP_TRAILING_WHITESPACE
		ERROR_QUIET)
	if(repository_result EQUAL 0 AND repository_output STREQUAL "true")
		execute_process(
			COMMAND "${GIT_EXECUTABLE}" rev-parse --short HEAD
			WORKING_DIRECTORY "${SOURCE_DIRECTORY}"
			RESULT_VARIABLE hash_result
			OUTPUT_VARIABLE commit_hash
			OUTPUT_STRIP_TRAILING_WHITESPACE
			ERROR_QUIET)
		execute_process(
			COMMAND "${GIT_EXECUTABLE}" status --porcelain --untracked-files=no
			WORKING_DIRECTORY "${SOURCE_DIRECTORY}"
			RESULT_VARIABLE status_result
			OUTPUT_VARIABLE status_output
			OUTPUT_STRIP_TRAILING_WHITESPACE
			ERROR_QUIET)
		execute_process(
			COMMAND "${GIT_EXECUTABLE}" describe --tags --exact-match HEAD
			WORKING_DIRECTORY "${SOURCE_DIRECTORY}"
			RESULT_VARIABLE tag_result
			OUTPUT_QUIET
			ERROR_QUIET)
		if(hash_result EQUAL 0 AND status_result EQUAL 0)
			if(status_output)
				set(version_suffix "+${commit_hash}-dirty")
			elseif(NOT tag_result EQUAL 0)
				set(version_suffix "+${commit_hash}")
			endif()
		endif()
	endif()
endif()

set(header_content "#ifndef _MCRELAY_VERSION_H_INCLUDED_\n\n#define _MCRELAY_VERSION_H_INCLUDED_\n\n/* section: defines */\n#define MCRELAY_VERSION_SUFFIX\t\"${version_suffix}\"\n\n#endif\n")
get_filename_component(output_directory "${OUTPUT_FILE}" DIRECTORY)
file(MAKE_DIRECTORY "${output_directory}")
if(EXISTS "${OUTPUT_FILE}")
	file(READ "${OUTPUT_FILE}" existing_content)
endif()
if(NOT DEFINED existing_content OR NOT existing_content STREQUAL header_content)
	file(WRITE "${OUTPUT_FILE}" "${header_content}")
endif()
