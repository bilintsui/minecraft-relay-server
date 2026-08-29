/*
 * freadall.c: Tests for safe file loading semantics
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* section: headers (project) */
#include "basic.h"

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
static bool fifo_test(const char *directory) {
	char filename[256], link[256];
	void *data = NULL;
	pid_t child;
	struct timespec start, end;
	ssize_t size;
	snprintf(filename, sizeof(filename), "%s/pipe.bin", directory);
	snprintf(link, sizeof(link), "%s/pipe-link.bin", directory);
	CHECK(mkfifo(filename, 0600) == 0, "cannot create the FIFO probe");
	/* A reader-less FIFO is rejected without blocking when not allowed. */
	alarm(5);
	CHECK(freadall(filename, &data, false) == -1 && errno == FREADALL_ERFAIL, "a reader-less FIFO was not rejected");
	alarm(0);
	/* FIFO support does not relax the final-component symlink policy. */
	CHECK(symlink(filename, link) == 0, "cannot create the FIFO symlink");
	alarm(5);
	CHECK(freadall(link, &data, true) == -1 && errno == FREADALL_ERFAIL && data == NULL, "a symlinked FIFO was followed");
	alarm(0);
	/* An allowed FIFO waits for a late writer before opening, then delivers its payload; the writer must exist before the write-side open. */
	child = fork();
	CHECK(child != -1, "cannot fork the FIFO writer");
	if (child == 0) {
		int fd;
		ssize_t written;
		alarm(5);
		usleep(300000);
		fd = open(filename, O_WRONLY);
		written = (fd != -1) ? write(fd, "late", 4U) : -1;
		if (fd != -1) {
			close(fd);
		}
		_exit(written == 4 ? EXIT_SUCCESS : EXIT_FAILURE);
	}
	CHECK(clock_gettime(CLOCK_MONOTONIC, &start) == 0, "cannot sample the wait start");
	alarm(5);
	size = freadall(filename, &data, true);
	alarm(0);
	CHECK(clock_gettime(CLOCK_MONOTONIC, &end) == 0, "cannot sample the wait end");
	{
		int child_status = 0;
		CHECK(waitpid(child, &child_status, 0) == child && WIFEXITED(child_status) && WEXITSTATUS(child_status) == EXIT_SUCCESS, "the FIFO writer failed");
	}
	{
		int64_t elapsed_nanoseconds = ((int64_t)end.tv_sec - (int64_t)start.tv_sec) * 1000000000LL + (int64_t)end.tv_nsec - (int64_t)start.tv_nsec;
		CHECK(size == 4 && data != NULL && memcmp(data, "late", 4U) == 0 && elapsed_nanoseconds >= 200000000LL, "an allowed FIFO did not wait for its late writer");
	}
	free(data);
	data = NULL;
	CHECK(freadall(filename, &data, false) == -1 && errno == FREADALL_ERFAIL && data == NULL, "a FIFO was accepted by the type check");
	return true;
}

static void freadall_cleanup(const char *directory) {
	static const char *const names[] = { "regular.bin", "large.bin", "real.bin", "link.bin", "pipe.bin", "pipe-link.bin" };
	char filename[256];
	for (size_t index = 0; index < sizeof(names) / sizeof(names[0]); index++) {
		snprintf(filename, sizeof(filename), "%s/%s", directory, names[index]);
		(void)unlink(filename);
	}
	(void)rmdir(directory);
}

static bool oversize_test(const char *directory) {
	char filename[256];
	void *data = NULL;
	FILE *file;
	snprintf(filename, sizeof(filename), "%s/large.bin", directory);
	file = fopen(filename, "wb");
	CHECK(file != NULL, "cannot create the oversized file");
	CHECK(fseek(file, FREADALL_SLIMIT, SEEK_SET) == 0 && fputc('x', file) != EOF && fclose(file) == 0, "cannot size the oversized file");
	alarm(10);
	CHECK(freadall(filename, &data, false) == -1 && errno == FREADALL_ELARGE && data == NULL, "an oversized file was not rejected");
	alarm(0);
	return true;
}

static bool regular_test(const char *directory) {
	char filename[256];
	void *data = (void *)1;
	static const char payload[] = "mcrelay freadall regular payload";
	FILE *file;
	ssize_t size;
	snprintf(filename, sizeof(filename), "%s/regular.bin", directory);
	file = fopen(filename, "wb");
	CHECK(file != NULL && fwrite(payload, 1, sizeof(payload) - 1U, file) == sizeof(payload) - 1U && fclose(file) == 0, "cannot seed the regular file");
	size = freadall(filename, &data, false);
	CHECK(size == (ssize_t)(sizeof(payload) - 1U) && data != NULL && memcmp(data, payload, (size_t)size) == 0, "regular file content mismatch");
	free(data);
	/* An empty file yields a NULL buffer and a zero size. */
	file = fopen(filename, "wb");
	CHECK(file != NULL && fclose(file) == 0, "cannot truncate the regular file");
	size = freadall(filename, &data, false);
	CHECK(size == 0 && data == NULL, "empty file handling mismatch");
	/* A missing file and a directory are rejected without touching the destination. */
	data = (void *)1;
	CHECK(freadall("/nonexistent/mcrelay-probe", &data, false) == -1 && errno == FREADALL_ERFAIL && data == (void *)1, "a missing file was not rejected");
	CHECK(freadall(directory, &data, false) == -1 && errno == FREADALL_ERFAIL && data == (void *)1, "a directory was not rejected");
	return true;
}

static bool symlink_test(const char *directory) {
	char real[256], link[256];
	void *data = NULL;
	char content[8] = { 0 };
	FILE *file;
	snprintf(real, sizeof(real), "%s/real.bin", directory);
	snprintf(link, sizeof(link), "%s/link.bin", directory);
	file = fopen(real, "wb");
	CHECK(file != NULL && fwrite("keep", 1, 4U, file) == 4U && fclose(file) == 0, "cannot seed the symlink target");
	CHECK(symlink(real, link) == 0, "cannot create the symlink");
	alarm(5);
	CHECK(freadall(link, &data, false) == -1 && errno == FREADALL_ERFAIL, "a symlinked path was followed");
	alarm(0);
	CHECK(data == NULL, "a symlinked path produced a buffer");
	file = fopen(real, "rb");
	CHECK(file != NULL && fread(content, 1, 4U, file) == 4U && fclose(file) == 0 && strcmp(content, "keep") == 0, "the symlink target was disturbed");
	return true;
}

static bool run_all_tests(const char *directory) {
	CHECK(regular_test(directory), "regular file semantics failed");
	CHECK(oversize_test(directory), "oversize rejection failed");
	CHECK(symlink_test(directory), "symlink policy failed");
	CHECK(fifo_test(directory), "FIFO policy failed");
	return true;
}

/* section: functions (entry point) */
int main(void) {
	char directory[] = "/tmp/mcrelay-freadall-XXXXXX";
	bool result;
	if (mkdtemp(directory) == NULL) {
		fprintf(stderr, "cannot create the temporary directory (errno=%d)\n", errno);
		return EXIT_FAILURE;
	}
	result = run_all_tests(directory);
	freadall_cleanup(directory);
	return result ? EXIT_SUCCESS : EXIT_FAILURE;
}
