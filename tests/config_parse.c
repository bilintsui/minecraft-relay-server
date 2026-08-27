/*
 * config_parse.c: Tests for configuration proxy entry sanitization
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

/* section: global variables */
static size_t config_test_allocs = 0;
static size_t config_test_fail_at = 0;

/* section: functions (local) */
static void *config_test_malloc(size_t size) {
	config_test_allocs++;
	if ((config_test_fail_at != 0) && (config_test_allocs == config_test_fail_at)) {
		return NULL;
	}
	return malloc(size);
}

static bool proxy_entry_check(const conf *parsed, size_t index, const char *vhost, const char *address, bool has_port, int port) {
	const cJSON *entry = cJSON_GetArrayItem(parsed->proxy, (int)index);
	if ((entry == NULL) || !cJSON_IsObject(entry)) {
		fprintf(stderr, "proxy entry %zu missing\n", index);
		return false;
	}
	const cJSON *entry_vhost = cJSON_GetObjectItemCaseSensitive(entry, "vhost");
	if ((entry_vhost == NULL) || !cJSON_IsArray(entry_vhost) || (cJSON_GetArraySize(entry_vhost) != 1)) {
		fprintf(stderr, "proxy entry %zu vhost is not a single-member array\n", index);
		return false;
	}
	const cJSON *entry_member = cJSON_GetArrayItem(entry_vhost, 0);
	if ((entry_member == NULL) || !cJSON_IsString(entry_member) || (strcmp(entry_member->valuestring, vhost) != 0)) {
		fprintf(stderr, "proxy entry %zu has wrong vhost\n", index);
		return false;
	}
	const cJSON *entry_address = cJSON_GetObjectItemCaseSensitive(entry, "address");
	if ((entry_address == NULL) || !cJSON_IsString(entry_address) || (strcmp(entry_address->valuestring, address) != 0)) {
		fprintf(stderr, "proxy entry %zu has wrong address\n", index);
		return false;
	}
	const cJSON *entry_port = cJSON_GetObjectItemCaseSensitive(entry, "port");
	if (has_port) {
		if ((entry_port == NULL) || !cJSON_IsNumber(entry_port) || (entry_port->valueint != port)) {
			fprintf(stderr, "proxy entry %zu has wrong port\n", index);
			return false;
		}
	} else if (entry_port != NULL) {
		fprintf(stderr, "proxy entry %zu unexpectedly has a port\n", index);
		return false;
	}
	return true;
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
	static const char config_mixed[] = "{\"proxy\":["
		"{\"vhost\":\"bad1\"},"
		"{\"vhost\":\"kept1\",\"address\":\"up1.example\",\"port\":25565},"
		"{\"vhost\":\"skipped\",\"address\":\"x\",\"port\":99999},"
		"{\"vhost\":\"bad2\",\"port\":\"nope\"},"
		"{\"vhost\":\"kept2\",\"address\":\"up2.example\"},"
		"{\"vhost\":42,\"address\":\"z\"},"
		"{\"vhost\":[],\"address\":\"w\"},"
		"{\"vhost\":[7,\"kept3\"],\"address\":\"v\"},"
		"{\"vhost\":\"fractional\",\"address\":\"frac.example\",\"port\":1.5},"
		"{\"vhost\":\"negativefractional\",\"address\":\"negfrac.example\",\"port\":-0.5},"
		"{\"vhost\":\"kept3\",\"address\":\"up3.example\"},"
		"{\"vhost\":\"kept4\",\"address\":123},"
		"{\"vhost\":\"negport\",\"address\":\"up4.example\",\"port\":-1},"
		"{\"vhost\":\"tail\",\"address\":\"up5.example\",\"port\":25570}"
	"]}";
	static const char config_filtered_empty[] = "{\"proxy\":[{\"port\":\"bad\"},{\"vhost\":[]},{\"address\":\"only\"}]}";
	static const char config_literal_empty[] = "{\"proxy\":[]}";
	static const char config_duplicate[] = "{\"proxy\":[{\"vhost\":\"dup.example\",\"address\":\"a.example\",\"port\":1},{\"vhost\":\"DUP.example\",\"address\":\"b.example\",\"port\":2}]}";
	static const char *config_invalid_listen[] = {
		"{\"listen\":{\"port\":1.5},\"proxy\":[{\"vhost\":\"test.example\",\"address\":\"up.example\"}]}",
		"{\"listen\":{\"port\":-0.5},\"proxy\":[{\"vhost\":\"test.example\",\"address\":\"up.example\"}]}",
		"{\"listen\":{\"port\":\"25565\"},\"proxy\":[{\"vhost\":\"test.example\",\"address\":\"up.example\"}]}"
	};
	char filename[] = "/tmp/mcrelay-config-parse-XXXXXX";
	int fd = -1;
	int result = EXIT_FAILURE;
	conf_cache active_cache = { 0 };
	conf_cache candidate_cache = { 0 };
	conf *parsed = NULL;
	conf_read_status status;
	size_t alloc_total = 0;
	cJSON_Hooks config_hooks = { .malloc_fn = config_test_malloc, .free_fn = free };

	fd = mkstemp(filename);
	CHECK(fd != -1, "cannot create temporary configuration file");

	CHECK(write_config(fd, config_mixed) == 0, "cannot write mixed configuration");
	status = config_read(filename, &active_cache, &candidate_cache, &parsed);
	CHECK(status == CONF_READ_CHANGED, "mixed configuration was rejected");
	CHECK(errno == 0, "mixed configuration returned an error");
	CHECK(parsed != NULL, "mixed configuration returned no object");
	CHECK(cJSON_IsArray(parsed->proxy) && (cJSON_GetArraySize(parsed->proxy) == 4), "mixed configuration kept wrong number of entries");
	CHECK(proxy_entry_check(parsed, 0, "kept1", "up1.example", true, 25565), "surviving entry 0 was corrupted");
	CHECK(proxy_entry_check(parsed, 1, "kept2", "up2.example", false, 0), "surviving entry 1 was corrupted");
	CHECK(proxy_entry_check(parsed, 2, "kept3", "up3.example", false, 0), "surviving entry 2 was corrupted");
	CHECK(proxy_entry_check(parsed, 3, "tail", "up5.example", true, 25570), "surviving entry 3 was corrupted");
	config_destroy(parsed);
	parsed = NULL;
	config_cache_destroy(&candidate_cache);

	CHECK(write_config(fd, config_filtered_empty) == 0, "cannot write filtered-empty configuration");
	status = config_read(filename, &active_cache, &candidate_cache, &parsed);
	CHECK(status == CONF_READ_ERROR, "configuration emptied by filtering was accepted");
	CHECK(errno == CONF_ECPROXY, "configuration emptied by filtering returned the wrong error");
	CHECK(parsed == NULL, "configuration emptied by filtering returned an object");
	config_cache_destroy(&candidate_cache);

	CHECK(write_config(fd, config_literal_empty) == 0, "cannot write literal-empty configuration");
	status = config_read(filename, &active_cache, &candidate_cache, &parsed);
	CHECK(status == CONF_READ_ERROR, "empty proxy list was accepted");
	CHECK(errno == CONF_ECPROXY, "empty proxy list returned the wrong error");
	CHECK(parsed == NULL, "empty proxy list returned an object");
	config_cache_destroy(&candidate_cache);

	CHECK(write_config(fd, config_duplicate) == 0, "cannot write duplicate configuration");
	status = config_read(filename, &active_cache, &candidate_cache, &parsed);
	CHECK(status == CONF_READ_ERROR, "duplicate vhosts were accepted");
	CHECK(errno == CONF_ECPROXYDUP, "duplicate vhosts returned the wrong error");
	CHECK(parsed == NULL, "duplicate vhosts returned an object");
	config_cache_destroy(&candidate_cache);
	for (size_t index = 0; index < sizeof(config_invalid_listen) / sizeof(config_invalid_listen[0]); index++) {
		CHECK(write_config(fd, config_invalid_listen[index]) == 0, "cannot write invalid listen-port configuration");
		status = config_read(filename, &active_cache, &candidate_cache, &parsed);
		CHECK(status == CONF_READ_ERROR, "invalid listen port was accepted");
		CHECK(errno == CONF_ECLISTENPORT, "invalid listen port returned the wrong error");
		CHECK(parsed == NULL, "invalid listen port returned an object");
		config_cache_destroy(&candidate_cache);
	}

	cJSON_InitHooks(&config_hooks);
	CHECK(write_config(fd, config_mixed) == 0, "cannot rewrite mixed configuration");
	config_test_allocs = 0;
	status = config_read(filename, &active_cache, &candidate_cache, &parsed);
	CHECK(status == CONF_READ_CHANGED, "counting configuration was rejected");
	alloc_total = config_test_allocs;
	CHECK(alloc_total > 0, "configuration parsing made no tracked allocations");
	config_destroy(parsed);
	parsed = NULL;
	config_cache_destroy(&candidate_cache);
	for (size_t fail_at = 1; fail_at <= alloc_total; fail_at++) {
		config_test_allocs = 0;
		config_test_fail_at = fail_at;
		status = config_read(filename, &active_cache, &candidate_cache, &parsed);
		config_test_fail_at = 0;
		CHECK((status == CONF_READ_ERROR) && (errno != 0) && (parsed == NULL)
			&& ((errno == CONF_ECMEMORY) || (errno == CONF_ERPARSE)),
			"allocation fault injection was tolerated");
		config_destroy(parsed);
		parsed = NULL;
		config_cache_destroy(&candidate_cache);
	}
	cJSON_InitHooks(NULL);

	result = EXIT_SUCCESS;

cleanup:
	config_destroy(parsed);
	config_cache_destroy(&active_cache);
	config_cache_destroy(&candidate_cache);
	if (fd != -1) {
		close(fd);
		unlink(filename);
	}
	return result;
}
