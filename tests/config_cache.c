/*
 * config_cache.c: Tests for configuration file caching
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <cjson/cJSON.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
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
static bool config_clone_test(void) {
	bool test_result = false;
	conf *clone = NULL;
	conf *source = calloc(1, sizeof(*source));
	CHECK(source != NULL, "cannot allocate clone source");
	source->log.filename = strdup("/tmp/clone.log");
	source->log.level = 4;
	source->listen.address = strdup("2001:db8::10");
	source->listen.port = 25570;
	source->icon_path = strdup("/tmp/icon.png");
	source->icon_b64 = strdup("YWJj");
	source->icon_cache.data = malloc(3);
	source->icon_cache.size = 3;
	source->proxy = cJSON_Parse("[{\"vhost\":[\"clone.example\"],\"address\":\"backend.example\",\"port\":25565}]");
	CHECK(source->log.filename != NULL && source->listen.address != NULL && source->icon_path != NULL && source->icon_b64 != NULL && source->icon_cache.data != NULL
		&& source->proxy != NULL, "cannot prepare clone source");
	memcpy(source->icon_cache.data, "abc", 3);
	CHECK(!config_clone(NULL, &clone) && errno == EINVAL && clone == NULL, "NULL clone source was accepted");
	CHECK(!config_clone(source, NULL) && errno == EINVAL, "NULL clone output was accepted");
	clone = (conf *)(uintptr_t)1;
	bool nonempty_accepted = config_clone(source, &clone);
	bool nonempty_preserved = clone == (conf *)(uintptr_t)1;
	clone = NULL;
	CHECK(!nonempty_accepted && errno == EINVAL && nonempty_preserved, "non-empty clone output was accepted or modified");
	CHECK(config_clone(source, &clone) && errno == 0 && clone != NULL, "configuration could not be cloned");
	CHECK(clone != source && clone->log.filename != source->log.filename && strcmp(clone->log.filename, source->log.filename) == 0 && clone->log.level == source->log.level,
		"cloned log configuration was shallow or incorrect");
	CHECK(clone->listen.address != source->listen.address && strcmp(clone->listen.address, source->listen.address) == 0 && clone->listen.port == source->listen.port,
		"cloned listener configuration was shallow or incorrect");
	CHECK(clone->icon_path != source->icon_path && strcmp(clone->icon_path, source->icon_path) == 0 && clone->icon_b64 != source->icon_b64
		&& strcmp(clone->icon_b64, source->icon_b64) == 0 && clone->icon_cache.data != source->icon_cache.data && clone->icon_cache.size == source->icon_cache.size
		&& memcmp(clone->icon_cache.data, source->icon_cache.data, source->icon_cache.size) == 0, "cloned icon state was shallow or incorrect");
	CHECK(clone->proxy != source->proxy && cJSON_Compare(clone->proxy, source->proxy, true), "cloned proxy configuration was shallow or incorrect");
	((char *)source->icon_cache.data)[0] = 'z';
	source->listen.address[0] = '1';
	cJSON_ReplaceItemInObject(cJSON_GetArrayItem(source->proxy, 0), "address", cJSON_CreateString("changed.example"));
	CHECK(memcmp(clone->icon_cache.data, "abc", 3) == 0 && strcmp(clone->listen.address, "2001:db8::10") == 0
		&& strcmp(cJSON_GetObjectItemCaseSensitive(cJSON_GetArrayItem(clone->proxy, 0), "address")->valuestring, "backend.example") == 0,
		"mutating clone source changed the cloned configuration");
	test_result = true;

cleanup:
	config_destroy(clone);
	config_destroy(source);
	return test_result;
}

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
	conf_cache active_cache = { 0 };
	conf_cache candidate_cache = { 0 };
	conf *parsed = NULL;
	conf icon_config = { 0 };
	void *cached_data = NULL;
	void *candidate_data = NULL;
	char *cached_icon_b64 = NULL;
	void *cached_icon_data = NULL;
	size_t cached_size = 0;
	CHECK(config_clone_test(), "configuration clone test failed");
	CHECK(sizeof(config_a) == sizeof(config_b), "test configurations must have equal lengths");
	fd = mkstemp(filename);
	CHECK(fd != -1, "cannot create temporary configuration file");
	CHECK(write_config(fd, config_a) == 0, "cannot write initial configuration");
	CHECK(config_read(filename, &active_cache, &candidate_cache, &parsed) == CONF_READ_CHANGED, "initial configuration was not parsed");
	CHECK((errno == 0) && (parsed != NULL), "initial configuration returned an error");
	CHECK(active_cache.data == NULL, "initial read modified the active cache before commit");
	candidate_data = candidate_cache.data;
	config_cache_commit(&active_cache, &candidate_cache);
	CHECK(active_cache.data == candidate_data, "initial candidate cache was not committed");
	CHECK((candidate_cache.data == NULL) && (candidate_cache.size == 0), "initial candidate cache retained ownership after commit");
	config_destroy(parsed);
	parsed = NULL;

	cached_data = active_cache.data;
	CHECK(config_read(filename, &active_cache, &candidate_cache, &parsed) == CONF_READ_UNCHANGED, "identical configuration was not detected");
	CHECK((errno == 0) && (parsed == NULL), "unchanged configuration returned a parsed object");
	CHECK(active_cache.data == cached_data, "unchanged configuration replaced the active cache");
	CHECK(candidate_cache.data == NULL, "unchanged configuration returned a candidate cache");

	CHECK(write_config(fd, config_b) == 0, "cannot write changed configuration");
	CHECK(config_read(filename, &active_cache, &candidate_cache, &parsed) == CONF_READ_CHANGED, "same-sized configuration change was not detected");
	CHECK((errno == 0) && (parsed != NULL), "changed configuration returned an error");
	CHECK(active_cache.data == cached_data, "changed configuration modified the active cache before commit");
	CHECK(memcmp(active_cache.data, config_a, active_cache.size) == 0, "changed configuration altered active cache content before commit");
	config_destroy(parsed);
	parsed = NULL;
	config_cache_destroy(&candidate_cache);
	CHECK(config_read(filename, &active_cache, &candidate_cache, &parsed) == CONF_READ_CHANGED, "discarded candidate was not retried");
	CHECK((errno == 0) && (parsed != NULL), "retried candidate returned an error");
	candidate_data = candidate_cache.data;
	config_cache_commit(&active_cache, &candidate_cache);
	CHECK(active_cache.data == candidate_data, "changed candidate cache was not committed");
	CHECK((candidate_cache.data == NULL) && (candidate_cache.size == 0), "changed candidate cache retained ownership after commit");
	config_destroy(parsed);
	parsed = NULL;

	cached_data = active_cache.data;
	cached_size = active_cache.size;
	CHECK(write_config(fd, config_invalid) == 0, "cannot write invalid configuration");
	CHECK(config_read(filename, &active_cache, &candidate_cache, &parsed) == CONF_READ_ERROR, "invalid configuration was accepted");
	CHECK(errno == CONF_ERPARSE, "invalid configuration returned the wrong error");
	CHECK(parsed == NULL, "invalid configuration returned a parsed object");
	CHECK((active_cache.data == cached_data) && (active_cache.size == cached_size), "invalid configuration replaced the active cache");
	CHECK(memcmp(active_cache.data, config_b, active_cache.size) == 0, "invalid configuration changed the active cached content");
	CHECK(candidate_cache.data == NULL, "invalid configuration returned a candidate cache");

	CHECK(write_config(fd, config_b) == 0, "cannot restore cached configuration");
	CHECK(config_read(filename, &active_cache, &candidate_cache, &parsed) == CONF_READ_UNCHANGED, "restored cached configuration was not detected");
	CHECK((errno == 0) && (parsed == NULL), "restored configuration returned an error");

	icon_config.icon_path = filename;
	CHECK(write_config(fd, "abc") == 0, "cannot write initial icon");
	CHECK(config_icon_load(&icon_config, MKSYS_NOLOGFILE, MKSYS_LEVEL_ALL, "using default"), "initial icon could not be loaded");
	CHECK((icon_config.icon_b64 != NULL) && (strcmp(icon_config.icon_b64, "YWJj") == 0), "initial icon was not loaded");
	cached_icon_b64 = icon_config.icon_b64;
	cached_icon_data = icon_config.icon_cache.data;
	CHECK(config_icon_load(&icon_config, MKSYS_NOLOGFILE, MKSYS_LEVEL_ALL, "keeping existing icon"), "unchanged icon returned an error");
	CHECK(icon_config.icon_b64 == cached_icon_b64, "unchanged icon was re-encoded");
	CHECK(icon_config.icon_cache.data == cached_icon_data, "unchanged icon replaced the raw cache");
	CHECK(write_config(fd, "xyz") == 0, "cannot write changed icon");
	CHECK(config_icon_load(&icon_config, MKSYS_NOLOGFILE, MKSYS_LEVEL_ALL, "keeping existing icon"), "changed icon could not be loaded");
	CHECK((icon_config.icon_b64 != NULL) && (strcmp(icon_config.icon_b64, "eHl6") == 0), "changed icon was not reloaded");
	CHECK((icon_config.icon_cache.size == 3) && (memcmp(icon_config.icon_cache.data, "xyz", 3) == 0), "changed icon did not replace the raw cache");

	cached_icon_b64 = icon_config.icon_b64;
	cached_icon_data = icon_config.icon_cache.data;
	CHECK(unlink(filename) == 0, "cannot remove icon file for read-failure test");
	CHECK(!config_icon_load(&icon_config, MKSYS_NOLOGFILE, MKSYS_LEVEL_ALL, "keeping existing icon"), "missing icon file did not return an error");
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
	config_cache_destroy(&active_cache);
	config_cache_destroy(&candidate_cache);
	if (fd != -1) {
		close(fd);
		unlink(filename);
	}
	return result;
}
