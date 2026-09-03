/*
 * route_prewarmer.c: Tests for bounded route DNS prewarm cursor management
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <cjson/cJSON.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* section: headers (project) */
#include "config.h"
#include "resolver/cache.h"
#include "resolver/hosts.h"
#include "route/bindings.h"
#include "route/prewarmer.h"
#include "route/table.h"

/* section: defines */
/* assertion */
#define CHECK(condition, message) \
	do { \
		if (!(condition)) { \
			fprintf(stderr, "%s\n", message); \
			goto cleanup; \
		} \
	} while (0)

/* section: functions (local) */
static bool prewarm_test_arguments(const route_bindings *bindings) {
	bool test_result = false;
	route_prewarmer prewarmer = { 0 };
	resolver_cache_entry *entry = (resolver_cache_entry *)(uintptr_t)1;
	CHECK(!route_prewarmer_complete(NULL) && !route_prewarmer_complete(&prewarmer), "invalid prewarmer appeared complete");
	CHECK(!route_prewarmer_entry_get(NULL, &entry) && entry == NULL && !route_prewarmer_entry_get(&prewarmer, &entry) && entry == NULL,
		"invalid prewarmer entry access was accepted");
	route_prewarmer_reset(NULL, bindings);
	route_prewarmer_reset(&prewarmer, bindings);
	CHECK(!route_prewarmer_entry_get(&prewarmer, NULL), "NULL entry output was accepted");
	prewarmer.next_entry_index = route_bindings_entry_count(bindings) + 1U;
	CHECK(!route_prewarmer_entry_get(&prewarmer, &entry) && entry == NULL && !route_prewarmer_advance(&prewarmer), "invalid cursor was accepted");
	test_result = true;

cleanup:
	return test_result;
}

static bool prewarm_test_cursor(const route_bindings *bindings) {
	bool test_result = false;
	route_prewarmer prewarmer = { 0 };
	resolver_cache_entry *entries[3] = { 0 };
	route_prewarmer_reset(&prewarmer, bindings);
	CHECK(route_bindings_entry_count(bindings) == 3, "prewarm fixture did not contain three entries");
	for (size_t entry_index = 0; entry_index < 3; entry_index++) {
		CHECK(route_bindings_entry_get(bindings, entry_index, &entries[entry_index]), "prewarm fixture entry could not be read");
	}
	for (size_t entry_index = 0; entry_index < 3; entry_index++) {
		resolver_cache_entry *entry = NULL;
		CHECK(!route_prewarmer_complete(&prewarmer) && route_prewarmer_entry_get(&prewarmer, &entry) && entry == entries[entry_index], "cursor returned the wrong entry");
		CHECK(route_prewarmer_advance(&prewarmer), "valid cursor did not advance");
	}
	CHECK(route_prewarmer_complete(&prewarmer) && prewarmer.next_entry_index == 3 && !route_prewarmer_advance(&prewarmer), "cursor completion state was incorrect");
	resolver_cache_entry *entry = (resolver_cache_entry *)(uintptr_t)1;
	CHECK(!route_prewarmer_entry_get(&prewarmer, &entry) && entry == NULL, "completed cursor returned a duplicate entry");
	route_prewarmer_reset(&prewarmer, NULL);
	CHECK(!route_prewarmer_complete(&prewarmer) && !route_prewarmer_entry_get(&prewarmer, &entry) && entry == NULL, "reset did not clear cursor ownership");
	test_result = true;

cleanup:
	return test_result;
}

/* section: functions (entry point) */
int main(void) {
	static const char json[] = "["
		"{\"vhost\":[\"address\"],\"address\":\"dns.example\",\"port\":25565},"
		"{\"vhost\":[\"srv\"],\"address\":\"service.example\"}"
	"]";
	int test_result = EXIT_FAILURE;
	conf config = { 0 };
	resolver_cache *cache = NULL;
	hosts_table *hosts = NULL;
	route_bindings *bindings = NULL;
	route_table *routes = NULL;
	size_t malformed_line_count = 0;
	config.proxy = cJSON_Parse(json);
	cache = resolver_cache_create();
	CHECK(config.proxy != NULL && cache != NULL, "prewarm fixture allocation failed");
	CHECK(hosts_table_load("/definitely/missing/mcrelay-hosts", &hosts, &malformed_line_count) == HOSTS_LOAD_FILE_ERROR && hosts != NULL,
		"prewarm hosts fixture could not be prepared");
	CHECK(route_table_build(&config, &routes) == ROUTE_TABLE_BUILD_OK && routes != NULL, "prewarm route table could not be prepared");
	CHECK(route_bindings_build(routes, hosts, cache, &bindings) == ROUTE_BINDINGS_BUILD_OK && bindings != NULL, "prewarm bindings could not be prepared");
	CHECK(prewarm_test_arguments(bindings) && prewarm_test_cursor(bindings), "prewarm cursor tests failed");
	test_result = EXIT_SUCCESS;

cleanup:
	route_bindings_destroy(bindings);
	resolver_cache_destroy(cache);
	route_table_destroy(routes);
	hosts_table_destroy(hosts);
	cJSON_Delete(config.proxy);
	return test_result;
}
