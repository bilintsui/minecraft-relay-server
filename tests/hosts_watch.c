/*
 * hosts_watch.c: Tests for local static host-name table file monitoring
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* section: headers (project) */
#include "resolver/hosts_watch.h"

/* section: defines */
#define HOSTS_WATCH_TEST_TIMEOUT_MS	2000

/* assertion */
#define CHECK(condition, message) \
	do { \
		if (!(condition)) { \
			fprintf(stderr, "%s (errno=%d)\n", message, errno); \
			goto cleanup; \
		} \
	} while (0)

/* section: functions (local) */
static bool hosts_watch_test_arguments(void) {
	bool result = false;
	hosts_watch *watch = NULL;
	hosts_watch_events events;
	CHECK(hosts_watch_create(NULL, &watch) == HOSTS_WATCH_CREATE_BAD_ARGUMENT && errno == EINVAL, "NULL filename was accepted");
	CHECK(hosts_watch_create("", &watch) == HOSTS_WATCH_CREATE_BAD_ARGUMENT && errno == EINVAL, "empty filename was accepted");
	CHECK(hosts_watch_create("/", &watch) == HOSTS_WATCH_CREATE_BAD_ARGUMENT && errno == EINVAL, "directory filename was accepted");
	CHECK(hosts_watch_create("missing", NULL) == HOSTS_WATCH_CREATE_BAD_ARGUMENT && errno == EINVAL, "NULL output was accepted");
	CHECK(hosts_watch_descriptor(NULL) == -1 && errno == EINVAL, "NULL descriptor source was accepted");
	CHECK(hosts_watch_read(NULL, &events) == HOSTS_WATCH_READ_BAD_ARGUMENT && errno == EINVAL, "NULL read source was accepted");
	CHECK(hosts_watch_read(watch, NULL) == HOSTS_WATCH_READ_BAD_ARGUMENT && errno == EINVAL, "NULL event output was accepted");
	hosts_watch_destroy(NULL);
	result = true;

cleanup:
	hosts_watch_destroy(watch);
	return result;
}

static bool hosts_watch_test_event_wait(hosts_watch *watch, bool changed, bool refresh) {
	struct pollfd descriptor = { .fd = hosts_watch_descriptor(watch), .events = POLLIN };
	int poll_result;
	do {
		poll_result = poll(&descriptor, 1, HOSTS_WATCH_TEST_TIMEOUT_MS);
	} while (poll_result == -1 && errno == EINTR);
	if (poll_result != 1 || !(descriptor.revents & POLLIN)) {
		errno = poll_result == 0 ? ETIMEDOUT : EIO;
		return false;
	}
	hosts_watch_events events;
	return hosts_watch_read(watch, &events) == HOSTS_WATCH_READ_OK && events.changed == changed && events.refresh == refresh;
}

static bool hosts_watch_test_file_write(const char *filename, const char *content) {
	int fd = open(filename, O_CLOEXEC | O_CREAT | O_TRUNC | O_WRONLY, 0600);
	if (fd == -1) {
		return false;
	}
	size_t size = strlen(content);
	ssize_t written = write(fd, content, size);
	int saved_errno = errno;
	if (close(fd) == -1 && written == (ssize_t)size) {
		return false;
	}
	errno = saved_errno;
	return written == (ssize_t)size;
}

static bool hosts_watch_test_hardlink_creation(const char *directory) {
	bool result = false;
	char filename[BUFSIZ] = { 0 };
	char ready[BUFSIZ] = { 0 };
	hosts_watch *watch = NULL;
	int length = snprintf(filename, sizeof(filename), "%s/hosts-hardlink", directory);
	CHECK(length > 0 && (size_t)length < sizeof(filename), "hardlink filename overflowed");
	length = snprintf(ready, sizeof(ready), "%s/hosts-ready", directory);
	CHECK(length > 0 && (size_t)length < sizeof(ready), "hardlink source filename overflowed");
	CHECK(hosts_watch_test_file_write(ready, "192.0.2.9 example.test\n"), "hardlink source could not be prepared");
	CHECK(hosts_watch_create(filename, &watch) == HOSTS_WATCH_CREATE_OK, "missing-hardlink watch could not be created");
	CHECK(link(ready, filename) == 0 && unlink(ready) == 0, "hosts hardlink could not be published and source removed");
	CHECK(hosts_watch_test_event_wait(watch, true, true), "hardlink publication was not reported as a change");
	result = true;

cleanup:
	hosts_watch_destroy(watch);
	unlink(filename);
	unlink(ready);
	return result;
}

static bool hosts_watch_test_monitoring(const char *directory) {
	bool result = false;
	char filename[BUFSIZ] = { 0 };
	hosts_watch *watch = NULL;
	char replacement[BUFSIZ] = { 0 };
	char sibling[BUFSIZ] = { 0 };
	int length = snprintf(filename, sizeof(filename), "%s/hosts", directory);
	CHECK(length > 0 && (size_t)length < sizeof(filename), "hosts filename overflowed");
	length = snprintf(replacement, sizeof(replacement), "%s/replacement", directory);
	CHECK(length > 0 && (size_t)length < sizeof(replacement), "replacement filename overflowed");
	length = snprintf(sibling, sizeof(sibling), "%s/sibling", directory);
	CHECK(length > 0 && (size_t)length < sizeof(sibling), "sibling filename overflowed");
	CHECK(hosts_watch_test_file_write(filename, "127.0.0.1 localhost\n"), "initial hosts file could not be written");
	CHECK(hosts_watch_create(filename, &watch) == HOSTS_WATCH_CREATE_OK, "hosts watch could not be created");
	CHECK(hosts_watch_test_file_write(sibling, "ignored\n"), "sibling file could not be written");
	CHECK(hosts_watch_test_event_wait(watch, false, false), "sibling event was not ignored");
	CHECK(hosts_watch_test_file_write(filename, "192.0.2.1 example.test\n"), "direct hosts update could not be written");
	CHECK(hosts_watch_test_event_wait(watch, true, true), "direct hosts update was not reported");
	hosts_watch_destroy(watch);
	watch = NULL;
	CHECK(hosts_watch_create(filename, &watch) == HOSTS_WATCH_CREATE_OK, "replacement hosts watch could not be created");
	CHECK(hosts_watch_test_file_write(replacement, "192.0.2.2 example.test\n") && rename(replacement, filename) == 0, "atomic hosts replacement failed");
	CHECK(hosts_watch_test_event_wait(watch, true, true), "atomic hosts replacement was not reported");
	hosts_watch_destroy(watch);
	watch = NULL;
	CHECK(hosts_watch_create(filename, &watch) == HOSTS_WATCH_CREATE_OK, "deletion hosts watch could not be created");
	CHECK(unlink(filename) == 0, "watched hosts file could not be deleted");
	CHECK(hosts_watch_test_event_wait(watch, true, true), "hosts deletion was not reported");
	hosts_watch_destroy(watch);
	watch = NULL;
	CHECK(hosts_watch_create(filename, &watch) == HOSTS_WATCH_CREATE_OK, "missing-file hosts watch could not be created");
	CHECK(hosts_watch_test_file_write(filename, "192.0.2.3 example.test\n"), "missing hosts file could not be recreated");
	CHECK(hosts_watch_test_event_wait(watch, true, true), "hosts recreation was not reported");
	result = true;

cleanup:
	hosts_watch_destroy(watch);
	unlink(filename);
	unlink(replacement);
	unlink(sibling);
	return result;
}

static bool hosts_watch_test_open_creation(const char *directory) {
	bool result = false;
	char filename[BUFSIZ] = { 0 };
	hosts_watch *watch = NULL;
	int fd = -1;
	int length = snprintf(filename, sizeof(filename), "%s/hosts-open", directory);
	CHECK(length > 0 && (size_t)length < sizeof(filename), "open-creation filename overflowed");
	CHECK(hosts_watch_create(filename, &watch) == HOSTS_WATCH_CREATE_OK, "open-creation watch could not be created");
	fd = open(filename, O_CLOEXEC | O_CREAT | O_EXCL | O_WRONLY, 0600);
	CHECK(fd >= 0, "watched regular file could not be created");
	CHECK(hosts_watch_test_event_wait(watch, true, true), "regular-file creation was not reported before close");
	const char content[] = "192.0.2.10 example.test\n";
	CHECK(write(fd, content, sizeof(content) - 1U) == (ssize_t)(sizeof(content) - 1U), "created regular file could not be written");
	CHECK(close(fd) == 0, "created regular file could not be closed");
	fd = -1;
	CHECK(hosts_watch_test_event_wait(watch, true, true), "regular-file close-write was not reported after creation");
	result = true;

cleanup:
	if (fd >= 0) {
		close(fd);
	}
	hosts_watch_destroy(watch);
	unlink(filename);
	return result;
}

static bool hosts_watch_test_overlap(const char *directory) {
	bool result = false;
	char filename[BUFSIZ] = { 0 };
	hosts_watch *candidate = NULL;
	hosts_watch *previous = NULL;
	int length = snprintf(filename, sizeof(filename), "%s/hosts-overlap", directory);
	CHECK(length > 0 && (size_t)length < sizeof(filename), "overlap filename overflowed");
	CHECK(hosts_watch_test_file_write(filename, "192.0.2.1 example.test\n"), "initial overlap file could not be written");
	CHECK(hosts_watch_create(filename, &previous) == HOSTS_WATCH_CREATE_OK, "previous overlap watch could not be created");
	CHECK(hosts_watch_test_file_write(filename, "192.0.2.2 example.test\n"), "overlap file could not be updated");
	CHECK(hosts_watch_create(filename, &candidate) == HOSTS_WATCH_CREATE_OK, "candidate overlap watch could not be created");
	CHECK(hosts_watch_test_event_wait(previous, true, true), "previous watch lost an event during candidate establishment");
	CHECK(hosts_watch_test_file_write(filename, "192.0.2.3 example.test\n"), "candidate overlap file could not be updated");
	CHECK(hosts_watch_test_event_wait(candidate, true, true), "candidate watch missed a later change");
	result = true;

cleanup:
	hosts_watch_destroy(candidate);
	hosts_watch_destroy(previous);
	unlink(filename);
	return result;
}

static bool hosts_watch_test_symlink(const char *directory) {
	bool result = false;
	char filename[BUFSIZ] = { 0 };
	hosts_watch *watch = NULL;
	char target[BUFSIZ] = { 0 };
	char target_directory[BUFSIZ] = { 0 };
	int length = snprintf(filename, sizeof(filename), "%s/hosts-link", directory);
	CHECK(length > 0 && (size_t)length < sizeof(filename), "symlink filename overflowed");
	length = snprintf(target_directory, sizeof(target_directory), "%s/targets", directory);
	CHECK(length > 0 && (size_t)length < sizeof(target_directory), "symlink target directory overflowed");
	CHECK(mkdir(target_directory, 0700) == 0, "symlink target directory could not be created");
	length = snprintf(target, sizeof(target), "%s/hosts-target", target_directory);
	CHECK(length > 0 && (size_t)length < sizeof(target), "symlink target overflowed");
	CHECK(hosts_watch_test_file_write(target, "192.0.2.4 example.test\n") && symlink("targets/hosts-target", filename) == 0, "hosts symlink fixture could not be created");
	CHECK(hosts_watch_create(filename, &watch) == HOSTS_WATCH_CREATE_OK, "symlink hosts watch could not be created");
	CHECK(hosts_watch_test_file_write(target, "192.0.2.5 example.test\n"), "symlink target could not be updated");
	CHECK(hosts_watch_test_event_wait(watch, true, true), "symlink target update was not reported");
	hosts_watch_destroy(watch);
	watch = NULL;
	CHECK(hosts_watch_create(filename, &watch) == HOSTS_WATCH_CREATE_OK, "target-deletion watch could not be created");
	CHECK(unlink(target) == 0, "symlink target could not be deleted");
	CHECK(hosts_watch_test_event_wait(watch, true, true), "symlink target deletion was not reported");
	hosts_watch_destroy(watch);
	watch = NULL;
	CHECK(hosts_watch_create(filename, &watch) == HOSTS_WATCH_CREATE_OK, "dangling-symlink watch could not be created");
	CHECK(hosts_watch_test_file_write(target, "192.0.2.6 example.test\n"), "symlink target could not be recreated");
	CHECK(hosts_watch_test_event_wait(watch, true, true), "symlink target recreation was not reported");
	hosts_watch_destroy(watch);
	watch = NULL;
	CHECK(hosts_watch_create(filename, &watch) == HOSTS_WATCH_CREATE_OK, "recreated-target watch could not be created");
	CHECK(hosts_watch_test_file_write(target, "192.0.2.7 example.test\n"), "recreated symlink target could not be updated");
	CHECK(hosts_watch_test_event_wait(watch, true, true), "recreated symlink target update was not reported");
	result = true;

cleanup:
	hosts_watch_destroy(watch);
	unlink(filename);
	unlink(target);
	rmdir(target_directory);
	return result;
}

static bool hosts_watch_test_symlink_creation(const char *directory) {
	bool result = false;
	char filename[BUFSIZ] = { 0 };
	char target[BUFSIZ] = { 0 };
	hosts_watch *watch = NULL;
	int length = snprintf(filename, sizeof(filename), "%s/new-link", directory);
	CHECK(length > 0 && (size_t)length < sizeof(filename), "new symlink filename overflowed");
	length = snprintf(target, sizeof(target), "%s/new-link-target", directory);
	CHECK(length > 0 && (size_t)length < sizeof(target), "new symlink target overflowed");
	CHECK(hosts_watch_test_file_write(target, "192.0.2.8 example.test\n"), "new symlink target could not be written");
	CHECK(hosts_watch_create(filename, &watch) == HOSTS_WATCH_CREATE_OK, "missing-symlink watch could not be created");
	CHECK(symlink(target, filename) == 0, "watched symlink could not be created");
	CHECK(hosts_watch_test_event_wait(watch, true, true), "symlink creation was not reported as a change");
	result = true;

cleanup:
	hosts_watch_destroy(watch);
	unlink(filename);
	unlink(target);
	return result;
}

/* section: functions (entry point) */
int main(void) {
	int result = EXIT_FAILURE;
	char directory[] = "/tmp/mcrelay-hosts-watch-XXXXXX";
	CHECK(mkdtemp(directory) != NULL, "temporary hosts-watch directory could not be created");
	CHECK(hosts_watch_test_arguments(), "hosts-watch argument tests failed");
	CHECK(hosts_watch_test_hardlink_creation(directory), "hosts-watch hardlink-creation tests failed");
	CHECK(hosts_watch_test_monitoring(directory), "hosts-watch monitoring tests failed");
	CHECK(hosts_watch_test_open_creation(directory), "hosts-watch open-creation tests failed");
	CHECK(hosts_watch_test_overlap(directory), "hosts-watch overlap tests failed");
	CHECK(hosts_watch_test_symlink(directory), "hosts-watch symlink tests failed");
	CHECK(hosts_watch_test_symlink_creation(directory), "hosts-watch symlink-creation tests failed");
	result = EXIT_SUCCESS;

cleanup:
	rmdir(directory);
	return result;
}
