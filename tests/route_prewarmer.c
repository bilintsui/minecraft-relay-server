/*
 * route_prewarmer.c: Tests for bounded route DNS prewarm scheduling
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
#include <string.h>
#include <time.h>

/* section: headers (project) */
#include "config.h"
#include "resolver/cache.h"
#include "resolver/hosts.h"
#include "resolver/supervisor.h"
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

/* section: types */
typedef struct {
	resolver_cache_entry *entry;
	resolver_supervisor_schedule_status status;
} prewarm_schedule_fixture;

/* section: global variables */
static size_t prewarm_schedule_fixture_count;
static size_t prewarm_schedule_fixture_index;
static prewarm_schedule_fixture prewarm_schedule_fixtures[8];
static resolver_supervisor *prewarm_schedule_supervisor;
static struct timespec prewarm_schedule_time;

/* section: functions (local) */
static void prewarm_schedule_reset(resolver_supervisor *supervisor, const struct timespec *now) {
	memset(prewarm_schedule_fixtures, 0, sizeof(prewarm_schedule_fixtures));
	prewarm_schedule_fixture_count = 0;
	prewarm_schedule_fixture_index = 0;
	prewarm_schedule_supervisor = supervisor;
	prewarm_schedule_time = *now;
}

static bool prewarm_test_arguments(const route_bindings *bindings, resolver_supervisor *supervisor, const struct timespec *now) {
	bool test_result = false;
	route_prewarmer prewarmer = { 0 };
	route_prewarm_step step;
	CHECK(!route_prewarmer_complete(NULL) && !route_prewarmer_complete(&prewarmer), "invalid prewarmer appeared complete");
	route_prewarmer_reset(NULL, bindings);
	CHECK(route_prewarmer_schedule(NULL, supervisor, now, 1) == ROUTE_PREWARM_BAD_ARGUMENT, "NULL prewarmer was accepted");
	route_prewarmer_reset(&prewarmer, bindings);
	CHECK(route_prewarmer_schedule(&prewarmer, NULL, now, 1) == ROUTE_PREWARM_BAD_ARGUMENT, "NULL supervisor was accepted");
	CHECK(route_prewarmer_schedule(&prewarmer, supervisor, NULL, 1) == ROUTE_PREWARM_BAD_ARGUMENT, "NULL time was accepted");
	CHECK(route_prewarmer_schedule(&prewarmer, supervisor, now, 0) == ROUTE_PREWARM_BAD_ARGUMENT, "zero batch limit was accepted");
	memset(&step, 0xFF, sizeof(step));
	CHECK(route_prewarmer_step(NULL, supervisor, now, &step) == ROUTE_PREWARM_BAD_ARGUMENT && step.entry == NULL && step.schedule_status == 0,
		"NULL step prewarmer was accepted or did not clear its result");
	CHECK(route_prewarmer_step(&prewarmer, NULL, now, &step) == ROUTE_PREWARM_BAD_ARGUMENT, "NULL step supervisor was accepted");
	CHECK(route_prewarmer_step(&prewarmer, supervisor, NULL, &step) == ROUTE_PREWARM_BAD_ARGUMENT, "NULL step time was accepted");
	CHECK(route_prewarmer_step(&prewarmer, supervisor, now, NULL) == ROUTE_PREWARM_BAD_ARGUMENT, "NULL step result was accepted");
	prewarmer.next_entry_index = route_bindings_entry_count(bindings) + 1U;
	CHECK(route_prewarmer_schedule(&prewarmer, supervisor, now, 1) == ROUTE_PREWARM_BAD_ARGUMENT, "invalid cursor was accepted");
	test_result = true;

cleanup:
	return test_result;
}

static bool prewarm_test_batches(const route_bindings *bindings, resolver_supervisor *supervisor, const struct timespec *now) {
	bool test_result = false;
	route_prewarmer prewarmer;
	route_prewarmer_reset(&prewarmer, bindings);
	prewarm_schedule_reset(supervisor, now);
	CHECK(route_bindings_entry_count(bindings) == 3, "prewarm fixture did not contain three entries");
	for (size_t entry_index = 0; entry_index < 3; entry_index++) {
		CHECK(route_bindings_entry_get(bindings, entry_index, &prewarm_schedule_fixtures[entry_index].entry), "prewarm fixture entry could not be read");
	}
	prewarm_schedule_fixtures[0].status = RESOLVER_SUPERVISOR_SCHEDULE_STARTED;
	prewarm_schedule_fixtures[1].status = RESOLVER_SUPERVISOR_SCHEDULE_FRESH;
	prewarm_schedule_fixtures[2].status = RESOLVER_SUPERVISOR_SCHEDULE_COMPLETE;
	prewarm_schedule_fixture_count = 3;
	CHECK(route_prewarmer_schedule(&prewarmer, supervisor, now, 2) == ROUTE_PREWARM_MORE && prewarmer.next_entry_index == 2 && !route_prewarmer_complete(&prewarmer),
		"first bounded prewarm wave was incorrect");
	CHECK(route_prewarmer_schedule(&prewarmer, supervisor, now, 2) == ROUTE_PREWARM_COMPLETE && prewarmer.next_entry_index == 3 && route_prewarmer_complete(&prewarmer),
		"final bounded prewarm wave was incorrect");
	CHECK(prewarm_schedule_fixture_index == prewarm_schedule_fixture_count, "prewarm wave made the wrong number of schedule calls");
	CHECK(route_prewarmer_schedule(&prewarmer, supervisor, now, 1) == ROUTE_PREWARM_COMPLETE && prewarm_schedule_fixture_index == 3,
		"complete prewarmer scheduled duplicate work");
	route_prewarm_step step = { .entry = (resolver_cache_entry *)(uintptr_t)1, .schedule_status = RESOLVER_SUPERVISOR_SCHEDULE_TIME };
	CHECK(route_prewarmer_step(&prewarmer, supervisor, now, &step) == ROUTE_PREWARM_COMPLETE && step.entry == NULL && step.schedule_status == 0,
		"complete prewarmer step retained stale output or scheduled duplicate work");
	test_result = true;

cleanup:
	return test_result;
}

static bool prewarm_test_capacity(const route_bindings *bindings, resolver_supervisor *supervisor, const struct timespec *now) {
	bool test_result = false;
	route_prewarmer prewarmer;
	resolver_cache_entry *entries[3] = { 0 };
	for (size_t entry_index = 0; entry_index < 3; entry_index++) {
		CHECK(route_bindings_entry_get(bindings, entry_index, &entries[entry_index]), "capacity fixture entry could not be read");
	}
	route_prewarmer_reset(&prewarmer, bindings);
	prewarm_schedule_reset(supervisor, now);
	prewarm_schedule_fixtures[0] = (prewarm_schedule_fixture){ .entry = entries[0], .status = RESOLVER_SUPERVISOR_SCHEDULE_COALESCED };
	prewarm_schedule_fixtures[1] = (prewarm_schedule_fixture){ .entry = entries[1], .status = RESOLVER_SUPERVISOR_SCHEDULE_LIMIT };
	prewarm_schedule_fixtures[2] = (prewarm_schedule_fixture){ .entry = entries[1], .status = RESOLVER_SUPERVISOR_SCHEDULE_STARTED };
	prewarm_schedule_fixtures[3] = (prewarm_schedule_fixture){ .entry = entries[2], .status = RESOLVER_SUPERVISOR_SCHEDULE_FRESH };
	prewarm_schedule_fixture_count = 4;
	CHECK(route_prewarmer_schedule(&prewarmer, supervisor, now, 3) == ROUTE_PREWARM_CAPACITY && prewarmer.next_entry_index == 1,
		"capacity stop consumed the rejected entry");
	CHECK(route_prewarmer_schedule(&prewarmer, supervisor, now, 3) == ROUTE_PREWARM_COMPLETE && prewarmer.next_entry_index == 3,
		"capacity-resumed wave did not retry the rejected entry");
	CHECK(prewarm_schedule_fixture_index == prewarm_schedule_fixture_count, "capacity-resumed wave made the wrong number of schedule calls");
	test_result = true;

cleanup:
	return test_result;
}

static bool prewarm_test_errors(const route_bindings *bindings, resolver_supervisor *supervisor, const struct timespec *now) {
	static const struct {
		resolver_supervisor_schedule_status input;
		route_prewarm_status output;
	} fixtures[] = {
		{ RESOLVER_SUPERVISOR_SCHEDULE_BAD_ARGUMENT, ROUTE_PREWARM_BAD_ARGUMENT },
		{ RESOLVER_SUPERVISOR_SCHEDULE_IO, ROUTE_PREWARM_IO },
		{ RESOLVER_SUPERVISOR_SCHEDULE_MEMORY, ROUTE_PREWARM_MEMORY },
		{ RESOLVER_SUPERVISOR_SCHEDULE_TIME, ROUTE_PREWARM_TIME }
	};
	bool test_result = false;
	resolver_cache_entry *entry = NULL;
	CHECK(route_bindings_entry_get(bindings, 0, &entry), "error fixture entry could not be read");
	for (size_t fixture_index = 0; fixture_index < sizeof(fixtures) / sizeof(fixtures[0]); fixture_index++) {
		route_prewarmer prewarmer;
		route_prewarmer_reset(&prewarmer, bindings);
		prewarm_schedule_reset(supervisor, now);
		prewarm_schedule_fixtures[0] = (prewarm_schedule_fixture){ .entry = entry, .status = fixtures[fixture_index].input };
		prewarm_schedule_fixture_count = 1;
		CHECK(route_prewarmer_schedule(&prewarmer, supervisor, now, 1) == fixtures[fixture_index].output && prewarmer.next_entry_index == 0,
			"prewarm error changed the cursor or returned the wrong status");
	}
	test_result = true;

cleanup:
	return test_result;
}

/* section: functions (exported) */
resolver_supervisor_schedule_status __wrap_resolver_supervisor_entry_schedule(resolver_supervisor *supervisor, resolver_cache_entry *entry, const struct timespec *now) {
	if (prewarm_schedule_fixture_index >= prewarm_schedule_fixture_count || supervisor != prewarm_schedule_supervisor || now == NULL
		|| now->tv_sec != prewarm_schedule_time.tv_sec || now->tv_nsec != prewarm_schedule_time.tv_nsec
		|| entry != prewarm_schedule_fixtures[prewarm_schedule_fixture_index].entry) {
		return RESOLVER_SUPERVISOR_SCHEDULE_BAD_ARGUMENT;
	}
	return prewarm_schedule_fixtures[prewarm_schedule_fixture_index++].status;
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
	struct timespec now = { .tv_sec = 100, .tv_nsec = 200 };
	resolver_supervisor *supervisor = (resolver_supervisor *)(uintptr_t)1;
	config.proxy = cJSON_Parse(json);
	cache = resolver_cache_create();
	CHECK(config.proxy != NULL && cache != NULL, "prewarm fixture allocation failed");
	CHECK(hosts_table_load("/definitely/missing/mcrelay-hosts", &hosts, &malformed_line_count) == HOSTS_LOAD_FILE_ERROR && hosts != NULL,
		"prewarm hosts fixture could not be prepared");
	CHECK(route_table_build(&config, &routes) == ROUTE_TABLE_BUILD_OK && routes != NULL, "prewarm route table could not be prepared");
	CHECK(route_bindings_build(routes, hosts, cache, &bindings) == ROUTE_BINDINGS_BUILD_OK && bindings != NULL, "prewarm bindings could not be prepared");
	CHECK(prewarm_test_arguments(bindings, supervisor, &now), "prewarm argument tests failed");
	CHECK(prewarm_test_batches(bindings, supervisor, &now), "prewarm batch tests failed");
	CHECK(prewarm_test_capacity(bindings, supervisor, &now), "prewarm capacity tests failed");
	CHECK(prewarm_test_errors(bindings, supervisor, &now), "prewarm error tests failed");
	test_result = EXIT_SUCCESS;

cleanup:
	route_bindings_destroy(bindings);
	resolver_cache_destroy(cache);
	route_table_destroy(routes);
	hosts_table_destroy(hosts);
	cJSON_Delete(config.proxy);
	return test_result;
}
