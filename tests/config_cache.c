/*
 * config_cache.c: Tests for configuration file caching
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/* section: headers (project) */
#include "config.h"
#include "log.h"

/* section: defines */
/* assertion */
#define CHECK(condition, message) \
	do { \
		if (!(condition)) { \
			fprintf(stderr, "%s (errno=%d)\n", message, errno); \
			goto cleanup; \
		} \
	} while (0)

/* section: functions (local) */
static int write_config(int fd, const char *content) {
	size_t length = strlen(content);
	if ((ftruncate(fd, 0) != 0) || (lseek(fd, 0, SEEK_SET) == -1)) {
		return -1;
	}
	size_t written = 0;
	while (written < length) {
		ssize_t result = write(fd, content + written, length - written);
		if (result <= 0) {
			return -1;
		}
		written += result;
	}
	return 0;
}

/* section: functions (entry point) */
int main(void) {
	static const char config_a[] = "{\"proxy\":[{\"vhost\":\"a.example\",\"address\":\"127.0.0.1\",\"port\":25565}]}";
	static const char config_b[] = "{\"proxy\":[{\"vhost\":\"b.example\",\"address\":\"127.0.0.1\",\"port\":25565}]}";
	static const char config_invalid[] = "not valid JSON";
	char filename[] = "/tmp/mcrelay-config-cache-XXXXXX";
	int fd = -1;
	int result = EXIT_FAILURE;
	conf_cache cache = { 0 };
	conf *parsed = NULL;
	conf icon_config = { 0 };
	void *cached_data = NULL;
	char *cached_icon_b64 = NULL;
	void *cached_icon_data = NULL;
	size_t cached_size = 0;
	CHECK(sizeof(config_a) == sizeof(config_b), "test configurations must have equal lengths");
	fd = mkstemp(filename);
	CHECK(fd != -1, "cannot create temporary configuration file");
	CHECK(write_config(fd, config_a) == 0, "cannot write initial configuration");
	CHECK(config_read(filename, &cache, &parsed) == CONF_READ_CHANGED, "initial configuration was not parsed");
	CHECK((errno == 0) && (parsed != NULL), "initial configuration returned an error");
	config_destroy(parsed);
	parsed = NULL;

	cached_data = cache.data;
	CHECK(config_read(filename, &cache, &parsed) == CONF_READ_UNCHANGED, "identical configuration was not detected");
	CHECK((errno == 0) && (parsed == NULL), "unchanged configuration returned a parsed object");
	CHECK(cache.data == cached_data, "unchanged configuration replaced the cache");

	CHECK(write_config(fd, config_b) == 0, "cannot write changed configuration");
	CHECK(config_read(filename, &cache, &parsed) == CONF_READ_CHANGED, "same-sized configuration change was not detected");
	CHECK((errno == 0) && (parsed != NULL), "changed configuration returned an error");
	config_destroy(parsed);
	parsed = NULL;

	cached_data = cache.data;
	cached_size = cache.size;
	CHECK(write_config(fd, config_invalid) == 0, "cannot write invalid configuration");
	CHECK(config_read(filename, &cache, &parsed) == CONF_READ_ERROR, "invalid configuration was accepted");
	CHECK(errno == CONF_ERPARSE, "invalid configuration returned the wrong error");
	CHECK(parsed == NULL, "invalid configuration returned a parsed object");
	CHECK((cache.data == cached_data) && (cache.size == cached_size), "invalid configuration replaced the cache");
	CHECK(memcmp(cache.data, config_b, cache.size) == 0, "invalid configuration changed the cached content");

	CHECK(write_config(fd, config_b) == 0, "cannot restore cached configuration");
	CHECK(config_read(filename, &cache, &parsed) == CONF_READ_UNCHANGED, "restored cached configuration was not detected");
	CHECK((errno == 0) && (parsed == NULL), "restored configuration returned an error");

	icon_config.icon_path = filename;
	CHECK(write_config(fd, "abc") == 0, "cannot write initial icon");
	config_icon_load(&icon_config, MKSYS_NOLOGFILE, MKSYS_LEVEL_ALL);
	CHECK((icon_config.icon_b64 != NULL) && (strcmp(icon_config.icon_b64, "YWJj") == 0), "initial icon was not loaded");
	cached_icon_b64 = icon_config.icon_b64;
	cached_icon_data = icon_config.icon_cache.data;
	config_icon_load(&icon_config, MKSYS_NOLOGFILE, MKSYS_LEVEL_ALL);
	CHECK(icon_config.icon_b64 == cached_icon_b64, "unchanged icon was re-encoded");
	CHECK(icon_config.icon_cache.data == cached_icon_data, "unchanged icon replaced the raw cache");
	CHECK(write_config(fd, "xyz") == 0, "cannot write changed icon");
	config_icon_load(&icon_config, MKSYS_NOLOGFILE, MKSYS_LEVEL_ALL);
	CHECK((icon_config.icon_b64 != NULL) && (strcmp(icon_config.icon_b64, "eHl6") == 0), "changed icon was not reloaded");
	CHECK((icon_config.icon_cache.size == 3) && (memcmp(icon_config.icon_cache.data, "xyz", 3) == 0), "changed icon did not replace the raw cache");

	cached_icon_b64 = icon_config.icon_b64;
	cached_icon_data = icon_config.icon_cache.data;
	CHECK(unlink(filename) == 0, "cannot remove icon file for read-failure test");
	config_icon_load(&icon_config, MKSYS_NOLOGFILE, MKSYS_LEVEL_ALL);
	CHECK(icon_config.icon_b64 == cached_icon_b64, "missing icon file cleared existing icon");
	CHECK(icon_config.icon_cache.data == cached_icon_data, "missing icon file invalidated the raw cache");

	result = EXIT_SUCCESS;

cleanup:
	/* icon_config.icon_path aliases the stack-allocated filename buffer,
	 * so config_destroy(&icon_config) (which would free icon_path) must
	 * not be called here; clean its owned fields directly instead. */
	free(icon_config.icon_b64);
	config_cache_destroy(&icon_config.icon_cache);
	config_destroy(parsed);
	config_cache_destroy(&cache);
	if (fd != -1) {
		close(fd);
		unlink(filename);
	}
	return result;
}
