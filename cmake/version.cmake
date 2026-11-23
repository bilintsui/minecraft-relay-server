if(NOT DEFINED OUTPUT_FILE)
	message(FATAL_ERROR "OUTPUT_FILE is required")
endif()
if(NOT DEFINED SOURCE_DIRECTORY)
	message(FATAL_ERROR "SOURCE_DIRECTORY is required")
endif()

set(version_suffix "")
set(source_is_repository FALSE)
get_filename_component(source_directory "${SOURCE_DIRECTORY}" REALPATH)
if(GIT_EXECUTABLE)
	execute_process(
		COMMAND "${GIT_EXECUTABLE}" rev-parse --show-toplevel
		WORKING_DIRECTORY "${source_directory}"
		RESULT_VARIABLE repository_result
		OUTPUT_VARIABLE repository_output
		OUTPUT_STRIP_TRAILING_WHITESPACE
		ERROR_QUIET)
	if(repository_result EQUAL 0)
		get_filename_component(repository_directory "${repository_output}" REALPATH)
		if(repository_directory STREQUAL source_directory)
			set(source_is_repository TRUE)
		endif()
	endif()
	if(source_is_repository)
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

if(NOT source_is_repository AND EXISTS "${source_directory}/cmake/archive-version.txt")
	# Read exported data as text, never as executable CMake. Unexpanded checkout
	# placeholders and invalid hashes supply no archive identity.
	file(READ "${source_directory}/cmake/archive-version.txt" archive_metadata)
	if(archive_metadata MATCHES "^commit=([0-9a-f]+)\nshort=([0-9a-f]+)\nrefs=([^\r\n]*)\n$")
		set(archive_commit "${CMAKE_MATCH_1}")
		set(archive_short "${CMAKE_MATCH_2}")
		set(archive_refs "${CMAKE_MATCH_3}")
		string(LENGTH "${archive_commit}" archive_commit_length)
		string(LENGTH "${archive_short}" archive_short_length)
		string(FIND "${archive_commit}" "${archive_short}" archive_short_position)
		string(FIND "${archive_refs}" "$Format:" archive_placeholder_position)
		if((archive_commit_length EQUAL 40 OR archive_commit_length EQUAL 64) AND archive_short_length GREATER_EQUAL 4 AND archive_short_position EQUAL 0 AND archive_placeholder_position EQUAL -1)
			if(NOT archive_refs MATCHES "(^|, )tag: ")
				set(version_suffix "+${archive_short}")
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
