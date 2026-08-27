/*
 * log_file.c: Tests for safe log file opening and appending
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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

/* section: functions (local) */
static bool file_contains(const char *filename, const char *needle) {
	char buffer[BUFSIZ];
	size_t total = 0;
	bool found;
	FILE *file = fopen(filename, "rb");
	if (file == NULL) {
		return false;
	}
	size_t received;
	while ((received = fread(buffer + total, 1, sizeof(buffer) - total - 1U, file)) > 0) {
		total += received;
		if (total >= sizeof(buffer) - 1U) {
			break;
		}
	}
	buffer[total] = '\0';
	found = fclose(file) == 0 && strstr(buffer, needle) != NULL;
	return found;
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

static bool directory_test(const char *directory) {
	errno = 0;
	CHECK(log_file_validate(directory) == -1 && errno == EISDIR, "validation accepted a directory path");
	(void)mksysmsg(MKSYS_PREFIX_ON, directory, MKSYS_LEVEL_ALL, MKSYS_LEVEL_INFORMATION, MKSYS_LINE_END, "never lands");
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
	reader = open(filename, O_RDONLY | O_NONBLOCK);
	CHECK(reader != -1, "cannot open the FIFO reader probe");
	CHECK(log_file_validate(filename) == -1 && errno == EIO, "FIFO was accepted by the type check");
	close(reader);
	reader = -1;
	alarm(0);
	return true;
}

static void log_file_cleanup(const char *directory) {
	static const char *const names[] = { "append.log", "pipe.log", "real.log", "link.log" };
	char filename[256];
	for (size_t index = 0; index < sizeof(names) / sizeof(names[0]); index++) {
		snprintf(filename, sizeof(filename), "%s/%s", directory, names[index]);
		(void)unlink(filename);
	}
	(void)rmdir(directory);
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
	(void)mksysmsg(MKSYS_PREFIX_ON, link, MKSYS_LEVEL_ALL, MKSYS_LEVEL_INFORMATION, MKSYS_LINE_END, "leak");
	CHECK(stat(real, &file_status) == 0 && file_status.st_size == 4, "symlink target size changed");
	file = fopen(real, "rb");
	CHECK(file != NULL && fread(content, 1, sizeof(content), file) == 4U && fclose(file) == 0, "symlink target is missing");
	CHECK(strcmp(content, "keep") == 0, "the symlink target was written through the link");
	return true;
}

static bool run_all_tests(const char *directory) {
	CHECK(append_test(directory), "append semantics failed");
	CHECK(directory_test(directory), "directory policy failed");
	CHECK(fifo_test(directory), "FIFO policy failed");
	CHECK(symlink_test(directory), "symlink policy failed");
	return true;
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
