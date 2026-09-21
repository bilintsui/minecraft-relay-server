/*
 * log_file.c: Tests for safe log file opening and appending
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* section: headers (project) */
#include "log.h"

/* section: defines */
/* assertion */
#define CHECK(condition, message) \
	do { \
		if (!(condition)) { \
			fprintf(stderr, "%s (errno=%d)\n", message, errno); \
			return false; \
		} \
	} while (0)

/* section: types */
typedef struct {
	bool enabled;
	size_t first;
	size_t index;
	size_t last;
} failure_schedule;

/* section: global variables */
static failure_schedule fclose_failure;
static int fclose_injected_fd = -1;
static failure_schedule fdopen_failure;
static int fdopen_injected_fd = -1;

/* section: functions (local) */
static bool failure_schedule_hit(failure_schedule *schedule) {
	if (!schedule->enabled) {
		return false;
	}
	size_t index = schedule->index;
	schedule->index++;
	return index >= schedule->first && index <= schedule->last;
}

static void failure_schedule_set(failure_schedule *schedule, bool enabled, size_t first, size_t last) {
	schedule->enabled = enabled;
	schedule->first = first;
	schedule->index = 0;
	schedule->last = last;
}

static bool file_read(const char *filename, char *buffer, size_t capacity, size_t *size) {
	if (capacity == 0) {
		errno = EINVAL;
		return false;
	}
	FILE *file = fopen(filename, "rb");
	if (file == NULL) {
		return false;
	}
	size_t received;
	size_t total = 0;
	while ((received = fread(buffer + total, 1, capacity - total - 1U, file)) > 0) {
		total += received;
		if (total >= capacity - 1U) {
			break;
		}
	}
	buffer[total] = '\0';
	if (fclose(file) != 0) {
		return false;
	}
	*size = total;
	return true;
}

static bool file_contains(const char *filename, const char *needle) {
	char buffer[BUFSIZ];
	size_t size;
	return file_read(filename, buffer, sizeof(buffer), &size) && strstr(buffer, needle) != NULL;
}

static bool file_seed(const char *filename, const char *content) {
	FILE *file = fopen(filename, "wb");
	if (file == NULL) {
		return false;
	}
	size_t size = strlen(content);
	bool written = fwrite(content, 1, size, file) == size;
	return fclose(file) == 0 && written;
}

static bool file_size(const char *filename, off_t *size) {
	struct stat file_status;
	if (stat(filename, &file_status) == -1) {
		return false;
	}
	*size = file_status.st_size;
	return true;
}

static bool process_wait_success(pid_t process_id) {
	int status;
	pid_t waited;
	do {
		waited = waitpid(process_id, &status, 0);
	} while (waited == -1 && errno == EINTR);
	return waited == process_id && WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS;
}

static bool rlimit_log_failure(const char *filename, rlim_t limit) {
	pid_t process_id = fork();
	if (process_id == -1) {
		return false;
	}
	if (process_id == 0) {
		struct rlimit file_limit;
		struct sigaction action;
		memset(&action, 0, sizeof(action));
		action.sa_handler = SIG_IGN;
		sigemptyset(&action.sa_mask);
		if (sigaction(SIGXFSZ, &action, NULL) == -1 || getrlimit(RLIMIT_FSIZE, &file_limit) == -1 || limit > file_limit.rlim_max) {
			_exit(EXIT_FAILURE);
		}
		file_limit.rlim_cur = limit;
		if (setrlimit(RLIMIT_FSIZE, &file_limit) == -1) {
			_exit(EXIT_FAILURE);
		}
		int result = mksysmsg(MKSYS_PREFIX_ON, filename, MKSYS_LEVEL_ALL, MKSYS_LEVEL_INFORMATION, MKSYS_LINE_END, "rlimit failure probe");
		_exit(result == 1 ? EXIT_SUCCESS : EXIT_FAILURE);
	}
	return process_wait_success(process_id);
}

static bool append_test(const char *directory) {
	char filename[256];
	struct stat file_status;
	snprintf(filename, sizeof(filename), "%s/append.log", directory);
	CHECK(log_file_validate(filename) == 0, "validation of a fresh log path failed");
	/* The validated file is created and kept in place instead of being probed and unlinked. */
	CHECK(stat(filename, &file_status) == 0 && file_status.st_size == 0, "validated log file was not kept in place");
	CHECK(mksysmsg(MKSYS_PREFIX_ON, filename, MKSYS_LEVEL_ALL, MKSYS_LEVEL_INFORMATION, MKSYS_LINE_END, "first line") == 0, "first append failed");
	CHECK(mksysmsg(MKSYS_PREFIX_ON, filename, MKSYS_LEVEL_ALL, MKSYS_LEVEL_INFORMATION, MKSYS_LINE_END, "second line") == 0, "second append failed");
	CHECK(file_contains(filename, "[INFO] first line") && file_contains(filename, "[INFO] second line"), "appended lines were not written");
	return true;
}

static bool console_failure_test(void) {
	pid_t process_id = fork();
	CHECK(process_id != -1, "cannot fork the console failure probe");
	if (process_id == 0) {
		if (close(STDERR_FILENO) == -1) {
			_exit(EXIT_FAILURE);
		}
		int result = mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_CRITICAL, MKSYS_LINE_END, "console failure probe");
		_exit(result == 1 ? EXIT_SUCCESS : EXIT_FAILURE);
	}
	CHECK(process_wait_success(process_id), "console sink failure was not reported");
	return true;
}

static bool directory_test(const char *directory) {
	errno = 0;
	CHECK(log_file_validate(directory) == -1 && errno == EISDIR, "validation accepted a directory path");
	CHECK(mksysmsg(MKSYS_PREFIX_ON, directory, MKSYS_LEVEL_ALL, MKSYS_LEVEL_INFORMATION, MKSYS_LINE_END, "never lands") == 1, "directory open failure was not reported");
	return true;
}

static bool fdopen_failure_test(const char *directory) {
	char filename[256];
	off_t initial_size;
	off_t final_size;
	snprintf(filename, sizeof(filename), "%s/fdopen.log", directory);
	CHECK(log_file_validate(filename) == 0 && file_size(filename, &initial_size), "cannot prepare the fdopen failure probe");
	fdopen_injected_fd = -1;
	failure_schedule_set(&fdopen_failure, true, 0, 0);
	int result = mksysmsg(MKSYS_PREFIX_ON, filename, MKSYS_LEVEL_ALL, MKSYS_LEVEL_INFORMATION, MKSYS_LINE_END, "fdopen failure probe");
	failure_schedule_set(&fdopen_failure, false, 0, 0);
	CHECK(result == 1, "fdopen failure was not reported");
	CHECK(fdopen_injected_fd >= 0, "fdopen failure was not injected");
	errno = 0;
	CHECK(fcntl(fdopen_injected_fd, F_GETFD) == -1 && errno == EBADF, "fdopen failure leaked the log descriptor");
	CHECK(file_size(filename, &final_size) && final_size == initial_size, "fdopen failure wrote a log line");
	CHECK(mksysmsg(MKSYS_PREFIX_ON, filename, MKSYS_LEVEL_ALL, MKSYS_LEVEL_INFORMATION, MKSYS_LINE_END, "fdopen recovered") == 0, "logging did not recover after fdopen injection");
	return true;
}

static bool fifo_test(const char *directory) {
	char filename[256];
	int reader = -1;
	/* The alarm covers every open below: removing O_NONBLOCK would otherwise hang the whole test. */
	alarm(5);
	snprintf(filename, sizeof(filename), "%s/pipe.log", directory);
	CHECK(mkfifo(filename, 0600) == 0, "cannot create the FIFO probe");
	CHECK(log_file_validate(filename) == -1 && errno == ENXIO, "reader-less FIFO did not fail at open");
	CHECK(mksysmsg(MKSYS_PREFIX_ON, filename, MKSYS_LEVEL_ALL, MKSYS_LEVEL_INFORMATION, MKSYS_LINE_END, "never lands") == 1, "reader-less FIFO failure was not reported");
	reader = open(filename, O_RDONLY | O_NONBLOCK);
	CHECK(reader != -1, "cannot open the FIFO reader probe");
	CHECK(log_file_validate(filename) == -1 && errno == EIO, "FIFO was accepted by the type check");
	CHECK(mksysmsg(MKSYS_PREFIX_ON, filename, MKSYS_LEVEL_ALL, MKSYS_LEVEL_INFORMATION, MKSYS_LINE_END, "never lands") == 1, "FIFO type failure was not reported");
	close(reader);
	reader = -1;
	alarm(0);
	return true;
}

static bool filter_test(const char *directory) {
	char filename[256];
	snprintf(filename, sizeof(filename), "%s/missing/filter.log", directory);
	CHECK(mksysmsg(MKSYS_PREFIX_ON, filename, MKSYS_LEVEL_CRITICAL, MKSYS_LEVEL_INFORMATION, MKSYS_LINE_END, "filtered") == 0, "filtered line reported an unattempted sink failure");
	return true;
}

static bool fclose_failure_test(const char *directory) {
	char filename[256];
	snprintf(filename, sizeof(filename), "%s/fclose.log", directory);
	CHECK(log_file_validate(filename) == 0, "cannot prepare the fclose failure probe");
	fclose_injected_fd = -1;
	failure_schedule_set(&fclose_failure, true, 1, 2);
	CHECK(mksysmsg(MKSYS_PREFIX_ON, filename, MKSYS_LEVEL_ALL, MKSYS_LEVEL_INFORMATION, MKSYS_LINE_END, "close call zero") == 0, "fclose schedule failed before its range");
	CHECK(mksysmsg(MKSYS_PREFIX_ON, filename, MKSYS_LEVEL_ALL, MKSYS_LEVEL_INFORMATION, MKSYS_LINE_END, "close call one") == 1, "first scheduled fclose failure was not reported");
	CHECK(mksysmsg(MKSYS_PREFIX_ON, filename, MKSYS_LEVEL_ALL, MKSYS_LEVEL_INFORMATION, MKSYS_LINE_END, "close call two") == 1, "second scheduled fclose failure was not reported");
	CHECK(mksysmsg(MKSYS_PREFIX_ON, filename, MKSYS_LEVEL_ALL, MKSYS_LEVEL_INFORMATION, MKSYS_LINE_END, "close call three") == 0, "fclose schedule remained active past its range");
	failure_schedule_set(&fclose_failure, false, 0, 0);
	CHECK(fclose_injected_fd >= 0, "fclose failure was not injected");
	errno = 0;
	CHECK(fcntl(fclose_injected_fd, F_GETFD) == -1 && errno == EBADF, "fclose injection leaked the log descriptor");
	CHECK(file_contains(filename, "close call zero") && file_contains(filename, "close call one") && file_contains(filename, "close call two") && file_contains(filename, "close call three"),
		"post-close failure incorrectly implied that a line was absent");
	return true;
}

static void log_file_cleanup(const char *directory) {
	static const char *const names[] = { "append.log", "fdopen.log", "fclose.log", "partial.log", "pipe.log", "real.log", "link.log", "zero.log" };
	char filename[256];
	for (size_t index = 0; index < sizeof(names) / sizeof(names[0]); index++) {
		snprintf(filename, sizeof(filename), "%s/%s", directory, names[index]);
		(void)unlink(filename);
	}
	(void)rmdir(directory);
}

static bool prefix_off_failure_test(const char *directory) {
	char filename[256];
	snprintf(filename, sizeof(filename), "%s/missing/prefix-off.log", directory);
	CHECK(mksysmsg(MKSYS_PREFIX_OFF, filename, MKSYS_LEVEL_ALL, MKSYS_LEVEL_INFORMATION, MKSYS_LINE_END, "prefix-off failure") == 1,
		"prefix-off non-TTY path discarded the file sink failure");
	return true;
}

static bool rlimit_failure_test(const char *directory) {
	char buffer[BUFSIZ];
	char partial_filename[256];
	char zero_filename[256];
	const char seed[] = "seed";
	const off_t partial_bytes = 7;
	off_t baseline;
	off_t size;
	size_t read_size;
	snprintf(partial_filename, sizeof(partial_filename), "%s/partial.log", directory);
	snprintf(zero_filename, sizeof(zero_filename), "%s/zero.log", directory);
	CHECK(file_seed(zero_filename, seed) && file_size(zero_filename, &baseline), "cannot prepare the zero-byte RLIMIT_FSIZE probe");
	CHECK(rlimit_log_failure(zero_filename, (rlim_t)baseline), "zero-byte RLIMIT_FSIZE failure was not reported");
	CHECK(file_size(zero_filename, &size) && size == baseline, "zero-byte RLIMIT_FSIZE probe changed the file");
	CHECK(file_seed(partial_filename, seed), "cannot prepare the partial RLIMIT_FSIZE probe");
	CHECK(rlimit_log_failure(partial_filename, (rlim_t)(baseline + partial_bytes)), "partial RLIMIT_FSIZE failure was not reported");
	CHECK(file_size(partial_filename, &size) && size == baseline + partial_bytes, "partial RLIMIT_FSIZE probe wrote the wrong byte count");
	CHECK(file_read(partial_filename, buffer, sizeof(buffer), &read_size) && read_size == (size_t)size && buffer[baseline] == '['
		&& memchr(buffer + baseline, '\n', (size_t)partial_bytes) == NULL, "partial RLIMIT_FSIZE probe did not leave an unterminated prefix");
	CHECK(mksysmsg(MKSYS_PREFIX_ON, partial_filename, MKSYS_LEVEL_ALL, MKSYS_LEVEL_INFORMATION, MKSYS_LINE_END, "after partial") == 0,
		"logging did not recover after the RLIMIT_FSIZE child exited");
	CHECK(file_read(partial_filename, buffer, sizeof(buffer), &read_size) && read_size > (size_t)(baseline + partial_bytes) && buffer[baseline + partial_bytes] == '[',
		"the next complete record was not glued directly to the truncated record");
	return true;
}

static bool symlink_test(const char *directory) {
	char real[256];
	char link[256];
	char content[16] = { 0 };
	struct stat file_status;
	FILE *file;
	snprintf(real, sizeof(real), "%s/real.log", directory);
	snprintf(link, sizeof(link), "%s/link.log", directory);
	file = fopen(real, "wb");
	CHECK(file != NULL && fwrite("keep", 1, 4U, file) == 4U && fclose(file) == 0, "cannot seed the symlink target");
	CHECK(symlink(real, link) == 0, "cannot create the log symlink");
	CHECK(log_file_validate(link) == -1 && errno == ELOOP, "validation accepted a symlinked log path");
	CHECK(mksysmsg(MKSYS_PREFIX_ON, link, MKSYS_LEVEL_ALL, MKSYS_LEVEL_INFORMATION, MKSYS_LINE_END, "leak") == 1, "symlink open failure was not reported");
	CHECK(stat(real, &file_status) == 0 && file_status.st_size == 4, "symlink target size changed");
	file = fopen(real, "rb");
	CHECK(file != NULL && fread(content, 1, sizeof(content), file) == 4U && fclose(file) == 0, "symlink target is missing");
	CHECK(strcmp(content, "keep") == 0, "the symlink target was written through the link");
	return true;
}

static bool run_all_tests(const char *directory) {
	CHECK(append_test(directory), "append semantics failed");
	CHECK(console_failure_test(), "console failure semantics failed");
	CHECK(directory_test(directory), "directory policy failed");
	CHECK(fdopen_failure_test(directory), "fdopen failure semantics failed");
	CHECK(fifo_test(directory), "FIFO policy failed");
	CHECK(filter_test(directory), "filter semantics failed");
	CHECK(fclose_failure_test(directory), "fclose failure semantics failed");
	CHECK(prefix_off_failure_test(directory), "prefix-off failure semantics failed");
	CHECK(rlimit_failure_test(directory), "RLIMIT_FSIZE failure semantics failed");
	CHECK(symlink_test(directory), "symlink policy failed");
	return true;
}

/* section: functions (exported) */
int __real_fclose(FILE *stream);
FILE *__real_fdopen(int fd, const char *mode);

int __wrap_fclose(FILE *stream) {
	int fd = fileno(stream);
	int result = __real_fclose(stream);
	if (failure_schedule_hit(&fclose_failure)) {
		fclose_injected_fd = fd;
		if (result == 0) {
			errno = EIO;
			return EOF;
		}
	}
	return result;
}

FILE *__wrap_fdopen(int fd, const char *mode) {
	if (failure_schedule_hit(&fdopen_failure)) {
		fdopen_injected_fd = fd;
		errno = EMFILE;
		return NULL;
	}
	return __real_fdopen(fd, mode);
}

/* section: functions (entry point) */
int main(void) {
	char directory[] = "/tmp/mcrelay-log-file-XXXXXX";
	bool result;
	if (mkdtemp(directory) == NULL) {
		fprintf(stderr, "cannot create the temporary directory (errno=%d)\n", errno);
		return EXIT_FAILURE;
	}
	result = run_all_tests(directory);
	log_file_cleanup(directory);
	return result ? EXIT_SUCCESS : EXIT_FAILURE;
}
