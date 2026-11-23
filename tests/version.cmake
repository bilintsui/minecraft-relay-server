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
	set(version_source "${repository_directory}")
	set(version_git "${GIT_EXECUTABLE}")
	if(ARGC GREATER 2)
		set(version_source "${ARGV2}")
	endif()
	if(ARGC GREATER 3)
		set(version_git "${ARGV3}")
	endif()
	execute_process(
		COMMAND "${CMAKE_COMMAND}"
			"-DGIT_EXECUTABLE=${version_git}"
			"-DOUTPUT_FILE=${output_file}"
			"-DSOURCE_DIRECTORY=${version_source}"
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

function(extract_archive destination revision)
	run_git(archive --format=tar --output "${state_directory}/source.tar" "${revision}")
	file(REMOVE_RECURSE "${destination}")
	file(MAKE_DIRECTORY "${destination}")
	execute_process(
		COMMAND "${CMAKE_COMMAND}" -E tar xf "${state_directory}/source.tar"
		WORKING_DIRECTORY "${destination}"
		RESULT_VARIABLE archive_result
		ERROR_VARIABLE archive_error)
	if(NOT archive_result EQUAL 0)
		message(FATAL_ERROR "archive extraction failed: ${archive_error}")
	endif()
endfunction()

function(read_commit_hash)
	execute_process(
		COMMAND "${GIT_EXECUTABLE}" rev-parse --short HEAD
		WORKING_DIRECTORY "${repository_directory}"
		RESULT_VARIABLE hash_result
		OUTPUT_VARIABLE hash_output
		OUTPUT_STRIP_TRAILING_WHITESPACE)
	if(NOT hash_result EQUAL 0)
		message(FATAL_ERROR "could not read test commit")
	endif()
	set(commit_hash "${hash_output}" PARENT_SCOPE)
endfunction()

if(NOT GIT_EXECUTABLE)
	message(FATAL_ERROR "Git is required for the version test")
endif()

set(state_directory "${TEST_DIRECTORY}/version-test-state")
set(repository_directory "${state_directory}/repository")
set(output_file "${state_directory}/version-test.h")
file(REMOVE_RECURSE "${state_directory}")
file(MAKE_DIRECTORY "${repository_directory}/cmake")
run_git(init)
run_git(config commit.gpgsign false)
run_git(config tag.gpgsign false)
run_git(config core.hooksPath /dev/null)
run_git(config user.email version-test@example.invalid)
run_git(config user.name "Version Test")
file(WRITE "${repository_directory}/tracked.txt" "initial\n")
# Keep the fixture placeholders here: the production metadata file itself is
# already substituted when this test runs from a committed source archive.
file(WRITE "${repository_directory}/cmake/archive-version.txt" "commit=$Format:%H$\nshort=$Format:%h$\nrefs=$Format:%D$\n")
get_filename_component(cmake_directory "${VERSION_SCRIPT}" DIRECTORY)
configure_file("${cmake_directory}/../.gitattributes" "${repository_directory}/.gitattributes" COPYONLY)
run_git(add tracked.txt .gitattributes cmake/archive-version.txt)
run_git(commit -m initial)
read_commit_hash()

assert_suffix("+${commit_hash}" "clean commit")
file(WRITE "${repository_directory}/untracked.txt" "not a tracked change\n")
assert_suffix("+${commit_hash}" "untracked files do not mark dirty")
assert_suffix("" "checkout without Git has unexpanded metadata" "${repository_directory}" "")

set(archive_directory "${state_directory}/archive")
extract_archive("${archive_directory}" HEAD)
assert_suffix("+${commit_hash}" "untagged archive" "${archive_directory}")
assert_suffix("+${commit_hash}" "untagged archive without Git" "${archive_directory}" "")
set(nested_directory "${repository_directory}/nested-archive")
extract_archive("${nested_directory}" HEAD)

run_git(tag test-version)
assert_suffix("" "tagged commit")
assert_suffix("+${commit_hash}" "archive ignores its now-tagged parent repository" "${nested_directory}")
extract_archive("${archive_directory}" HEAD)
assert_suffix("" "lightweight tagged archive" "${archive_directory}")
assert_suffix("" "tagged archive without Git" "${archive_directory}" "")
file(APPEND "${repository_directory}/tracked.txt" "dirty\n")
assert_suffix("+${commit_hash}-dirty" "dirty tagged commit")
extract_archive("${archive_directory}" HEAD)
assert_suffix("" "archive excludes dirty worktree changes" "${archive_directory}")
configure_file("${archive_directory}/cmake/archive-version.txt" "${repository_directory}/cmake/archive-version.txt" COPYONLY)
assert_suffix("+${commit_hash}-dirty" "live Git overrides exported metadata")
run_git(checkout -- tracked.txt cmake/archive-version.txt)
assert_suffix("" "restored tagged commit")

run_git(tag -d test-version)
run_git(tag -a annotated-version -m "annotated test tag")
extract_archive("${archive_directory}" annotated-version)
assert_suffix("" "annotated tagged archive" "${archive_directory}")
run_git(commit --allow-empty -m after-tag)
read_commit_hash()
assert_suffix("+${commit_hash}" "commit after a tag")
extract_archive("${archive_directory}" HEAD)
assert_suffix("+${commit_hash}" "archive after a tag" "${archive_directory}")

set(worktree_directory "${state_directory}/linked-worktree")
run_git(worktree add --detach "${worktree_directory}" HEAD)
assert_suffix("+${commit_hash}" "linked Git worktree" "${worktree_directory}")
set(symlink_directory "${state_directory}/source-link")
execute_process(COMMAND "${CMAKE_COMMAND}" -E create_symlink "${repository_directory}" "${symlink_directory}" RESULT_VARIABLE symlink_result)
if(NOT symlink_result EQUAL 0)
	message(FATAL_ERROR "could not create source-path symlink")
endif()
assert_suffix("+${commit_hash}" "symlinked Git worktree" "${symlink_directory}")

set(plain_directory "${repository_directory}/plain-source")
file(MAKE_DIRECTORY "${plain_directory}/cmake")
assert_suffix("" "plain source does not inherit a parent Git identity" "${plain_directory}")
file(WRITE "${plain_directory}/cmake/archive-version.txt" "set(version_suffix injected)\n")
assert_suffix("" "archive metadata is not executed" "${plain_directory}")
foreach(invalid_metadata
	"commit=0123456789abcdef0123456789abcdef01234567\nshort=badcafe\nrefs=\n"
	"commit=0123456789abcdef0123456789abcdef01234567\nshort=xyz\nrefs=\n"
	"commit=0123456789abcdef\nshort=0123456\nrefs=\n"
	"commit=0123456789abcdef0123456789abcdef01234567\nshort=0123456\nrefs=$Format:%D$\n"
	"commit=0123456789abcdef0123456789abcdef01234567\nshort=0123456\nrefs=\nextra=1\n")
	file(WRITE "${plain_directory}/cmake/archive-version.txt" "${invalid_metadata}")
	assert_suffix("" "invalid archive identity is ignored" "${plain_directory}")
endforeach()

extract_archive("${archive_directory}" HEAD^{tree})
assert_suffix("" "tree-only archive has no commit substitution" "${archive_directory}")
file(REMOVE_RECURSE "${state_directory}")
