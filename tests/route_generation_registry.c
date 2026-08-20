/*
 * route_generation_registry.c: Tests for bounded live route generations
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* section: headers (project) */
#include "resolver_supervisor.h"
#include "route_generation.h"
#include "route_generation_registry.h"
#include "route_resolution.h"

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
	size_t completion_count;
	route_resolution_completion_status completion_status;
	size_t dispose_count;
	uint64_t identity;
	size_t reference_count;
	size_t release_count;
	route_resolution *resolution;
	size_t retain_count;
} generation_registry_fixture;

/* section: global variables */
static generation_registry_fixture generation_fixtures[3];

/* section: functions (local) */
static generation_registry_fixture *generation_fixture_find(const route_generation *generation) {
	for (size_t fixture_index = 0; fixture_index < sizeof(generation_fixtures) / sizeof(generation_fixtures[0]); fixture_index++) {
		if (generation == (const route_generation *)&generation_fixtures[fixture_index]) {
			return &generation_fixtures[fixture_index];
		}
	}
	return NULL;
}

static generation_registry_fixture *generation_fixture_find_resolution(const route_resolution *resolution) {
	for (size_t fixture_index = 0; fixture_index < sizeof(generation_fixtures) / sizeof(generation_fixtures[0]); fixture_index++) {
		if (generation_fixtures[fixture_index].resolution == resolution) {
			return &generation_fixtures[fixture_index];
		}
	}
	return NULL;
}

static route_generation *generation_fixture_get(size_t fixture_index) {
	return fixture_index >= sizeof(generation_fixtures) / sizeof(generation_fixtures[0]) ? NULL : (route_generation *)&generation_fixtures[fixture_index];
}

static void generation_fixtures_reset(void) {
	static unsigned char resolution_storage[3];
	memset(generation_fixtures, 0, sizeof(generation_fixtures));
	for (size_t fixture_index = 0; fixture_index < sizeof(generation_fixtures) / sizeof(generation_fixtures[0]); fixture_index++) {
		generation_fixtures[fixture_index].completion_status = ROUTE_RESOLUTION_COMPLETION_IGNORED;
		generation_fixtures[fixture_index].identity = fixture_index + 1U;
		generation_fixtures[fixture_index].reference_count = 1;
		generation_fixtures[fixture_index].resolution = (route_resolution *)&resolution_storage[fixture_index];
	}
}

static bool generation_registry_test_arguments(void) {
	bool test_result = false;
	resolver_supervisor_completion completion = { 0 };
	route_generation_registry *registry = route_generation_registry_create();
	struct timespec now = { 0 };
	CHECK(registry != NULL, "argument-test generation registry could not be created");
	generation_fixtures_reset();
	CHECK(route_generation_registry_active(NULL) == NULL && route_generation_registry_active_retain(NULL) == NULL && !route_generation_registry_collect(NULL)
		&& route_generation_registry_retired(NULL) == NULL, "NULL generation registry accessors were not defensive");
	CHECK(route_generation_registry_completion_observe(NULL, &completion, &now) == ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT
		&& route_generation_registry_completion_observe(registry, NULL, &now) == ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT
		&& route_generation_registry_completion_observe(registry, &completion, NULL) == ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT,
		"invalid generation completion observation was accepted");
	CHECK(route_generation_registry_publish(NULL, generation_fixture_get(0)) == ROUTE_GENERATION_REGISTRY_PUBLISH_BAD_ARGUMENT
		&& route_generation_registry_publish(registry, NULL) == ROUTE_GENERATION_REGISTRY_PUBLISH_BAD_ARGUMENT, "invalid generation publication was accepted");
	generation_fixtures[0].identity = 0;
	CHECK(route_generation_registry_publish(registry, generation_fixture_get(0)) == ROUTE_GENERATION_REGISTRY_PUBLISH_BAD_ARGUMENT,
		"zero-identity candidate generation was accepted");
	generation_fixtures[0].identity = 1;
	generation_fixtures[0].reference_count = 2;
	CHECK(route_generation_registry_publish(registry, generation_fixture_get(0)) == ROUTE_GENERATION_REGISTRY_PUBLISH_BAD_ARGUMENT,
		"shared candidate generation was accepted");
	CHECK(route_generation_registry_completion_observe(registry, &completion, &now) == ROUTE_RESOLUTION_COMPLETION_IGNORED,
		"empty generation registry did not ignore a completion");
	route_generation_registry_destroy(NULL);
	route_generation_registry_dispose_in_child(NULL);
	test_result = true;

cleanup:
	route_generation_registry_destroy(registry);
	return test_result;
}

static bool generation_registry_test_completion(void) {
	bool test_result = false;
	resolver_supervisor_completion completion = { 0 };
	route_generation_registry *registry = route_generation_registry_create();
	struct timespec now = { .tv_sec = 10, .tv_nsec = 20 };
	CHECK(registry != NULL, "completion-test generation registry could not be created");
	generation_fixtures_reset();
	CHECK(route_generation_registry_publish(registry, generation_fixture_get(0)) == ROUTE_GENERATION_REGISTRY_PUBLISH_OK
		&& route_generation_registry_active_retain(registry) == generation_fixture_get(0)
		&& route_generation_registry_publish(registry, generation_fixture_get(1)) == ROUTE_GENERATION_REGISTRY_PUBLISH_OK,
		"completion-test generations could not be published");
	generation_fixtures[0].completion_status = ROUTE_RESOLUTION_COMPLETION_OK;
	generation_fixtures[1].completion_status = ROUTE_RESOLUTION_COMPLETION_IGNORED;
	CHECK(route_generation_registry_completion_observe(registry, &completion, &now) == ROUTE_RESOLUTION_COMPLETION_OK
		&& generation_fixtures[0].completion_count == 1 && generation_fixtures[1].completion_count == 1,
		"completion was not offered to both live generations");
	generation_fixtures[0].completion_status = ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT;
	generation_fixtures[1].completion_status = ROUTE_RESOLUTION_COMPLETION_OK;
	CHECK(route_generation_registry_completion_observe(registry, &completion, &now) == ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT
		&& generation_fixtures[0].completion_count == 2 && generation_fixtures[1].completion_count == 2,
		"bad completion status prevented full generation fan-out or was not propagated");
	route_generation_release(generation_fixture_get(0));
	CHECK(route_generation_registry_collect(registry), "unpinned completion-test retired generation was not collected");
	test_result = true;

cleanup:
	route_generation_registry_destroy(registry);
	return test_result;
}

static bool generation_registry_test_dispose_in_child(void) {
	bool test_result = false;
	route_generation_registry *registry = route_generation_registry_create();
	CHECK(registry != NULL, "child-dispose generation registry could not be created");
	generation_fixtures_reset();
	CHECK(route_generation_registry_publish(registry, generation_fixture_get(0)) == ROUTE_GENERATION_REGISTRY_PUBLISH_OK
		&& route_generation_registry_active_retain(registry) == generation_fixture_get(0)
		&& route_generation_registry_publish(registry, generation_fixture_get(1)) == ROUTE_GENERATION_REGISTRY_PUBLISH_OK,
		"child-dispose generations could not be published");
	route_generation_registry_dispose_in_child(registry);
	registry = NULL;
	CHECK(generation_fixtures[0].dispose_count == 1 && generation_fixtures[1].dispose_count == 1 && generation_fixtures[0].release_count == 0
		&& generation_fixtures[1].release_count == 0, "child dispose released references or did not destroy both private generation copies");
	test_result = true;

cleanup:
	route_generation_registry_destroy(registry);
	return test_result;
}

static bool generation_registry_test_publication(void) {
	bool test_result = false;
	route_generation_registry *registry = route_generation_registry_create();
	CHECK(registry != NULL, "publication-test generation registry could not be created");
	generation_fixtures_reset();
	route_generation *first = generation_fixture_get(0);
	route_generation *second = generation_fixture_get(1);
	route_generation *third = generation_fixture_get(2);
	CHECK(route_generation_registry_publish(registry, first) == ROUTE_GENERATION_REGISTRY_PUBLISH_OK && route_generation_registry_active(registry) == first
		&& route_generation_registry_retired(registry) == NULL, "initial generation publication was incorrect");
	CHECK(route_generation_registry_active_retain(registry) == first && generation_fixtures[0].reference_count == 2 && generation_fixtures[0].retain_count == 1,
		"active generation could not be pinned");
	CHECK(route_generation_registry_publish(registry, second) == ROUTE_GENERATION_REGISTRY_PUBLISH_OK && route_generation_registry_active(registry) == second
		&& route_generation_registry_retired(registry) == first, "replacement generation did not retain the pinned active generation");
	CHECK(route_generation_registry_publish(registry, third) == ROUTE_GENERATION_REGISTRY_PUBLISH_BLOCKED && route_generation_registry_active(registry) == second
		&& route_generation_registry_retired(registry) == first && generation_fixtures[2].reference_count == 1, "third generation bypassed the live-generation bound");
	CHECK(route_generation_release(first) == 1 && route_generation_registry_collect(registry) && route_generation_registry_retired(registry) == NULL
		&& generation_fixtures[0].reference_count == 0 && generation_fixtures[0].release_count == 2, "retired generation was not collected after its final external release");
	CHECK(route_generation_registry_publish(registry, third) == ROUTE_GENERATION_REGISTRY_PUBLISH_OK && route_generation_registry_active(registry) == third
		&& route_generation_registry_retired(registry) == NULL && generation_fixtures[1].reference_count == 0,
		"third generation was not published after retired collection or unpinned active generation was retained");
	generation_fixtures[1].identity = 4;
	generation_fixtures[1].reference_count = 1;
	CHECK(route_generation_registry_publish(registry, second) == ROUTE_GENERATION_REGISTRY_PUBLISH_OK && route_generation_registry_active(registry) == second,
		"newer generation identity was rejected");
	generation_fixtures[0].identity = 4;
	generation_fixtures[0].reference_count = 1;
	CHECK(route_generation_registry_publish(registry, first) == ROUTE_GENERATION_REGISTRY_PUBLISH_BAD_ARGUMENT,
		"non-increasing generation identity was accepted");
	test_result = true;

cleanup:
	route_generation_registry_destroy(registry);
	return test_result;
}

/* section: functions (exported) */
void __wrap_route_generation_dispose_in_child(route_generation *generation) {
	generation_registry_fixture *fixture = generation_fixture_find(generation);
	if (fixture != NULL) {
		fixture->dispose_count++;
	}
}

uint64_t __wrap_route_generation_identity(const route_generation *generation) {
	generation_registry_fixture *fixture = generation_fixture_find(generation);
	return fixture == NULL ? 0 : fixture->identity;
}

size_t __wrap_route_generation_reference_count(const route_generation *generation) {
	generation_registry_fixture *fixture = generation_fixture_find(generation);
	return fixture == NULL ? 0 : fixture->reference_count;
}

size_t __wrap_route_generation_release(route_generation *generation) {
	generation_registry_fixture *fixture = generation_fixture_find(generation);
	if (fixture == NULL || fixture->reference_count == 0) {
		return 0;
	}
	fixture->reference_count--;
	fixture->release_count++;
	return fixture->reference_count;
}

route_resolution *__wrap_route_generation_resolution(route_generation *generation) {
	generation_registry_fixture *fixture = generation_fixture_find(generation);
	return fixture == NULL ? NULL : fixture->resolution;
}

bool __wrap_route_generation_retain(route_generation *generation) {
	generation_registry_fixture *fixture = generation_fixture_find(generation);
	if (fixture == NULL || fixture->reference_count == SIZE_MAX) {
		return false;
	}
	fixture->reference_count++;
	fixture->retain_count++;
	return true;
}

route_resolution_completion_status __wrap_route_resolution_completion_observe(route_resolution *resolution, const resolver_supervisor_completion *completion,
	const struct timespec *now) {
	generation_registry_fixture *fixture = generation_fixture_find_resolution(resolution);
	if (fixture == NULL || completion == NULL || now == NULL) {
		return ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT;
	}
	fixture->completion_count++;
	return fixture->completion_status;
}

/* section: functions (entry point) */
int main(void) {
	if (!generation_registry_test_arguments() || !generation_registry_test_completion() || !generation_registry_test_dispose_in_child()
		|| !generation_registry_test_publication()) {
		return 1;
	}
	return 0;
}
