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
#include "resolver/supervisor.h"
#include "route/generation.h"
#include "route/generation_registry.h"
#include "route/resolution.h"

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
enum {
	TEST_RESOLUTION_OK,
	TEST_RESOLUTION_BAD_ARGUMENT,
	TEST_RESOLUTION_IO,
	TEST_RESOLUTION_TIME
};
typedef struct {
	int background_release_status;
	size_t background_release_count;
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
		generation_fixtures[fixture_index].background_release_status = TEST_RESOLUTION_OK;
		generation_fixtures[fixture_index].completion_status = ROUTE_RESOLUTION_COMPLETION_IGNORED;
		generation_fixtures[fixture_index].identity = fixture_index + 1U;
		generation_fixtures[fixture_index].reference_count = 1;
		generation_fixtures[fixture_index].resolution = (route_resolution *)&resolution_storage[fixture_index];
	}
}

static resolver_supervisor *generation_registry_supervisor(void) {
	return (resolver_supervisor *)(void *)&generation_fixtures[0];
}

static bool generation_registry_test_arguments(void) {
	bool test_result = false;
	resolver_supervisor_completion completion = { 0 };
	route_generation_registry *registry = route_generation_registry_create();
	struct timespec now = { 0 };
	struct timespec invalid_time = { .tv_sec = -1 };
	CHECK(registry != NULL, "argument-test generation registry could not be created");
	generation_fixtures_reset();
	CHECK(route_generation_registry_active(NULL) == NULL && route_generation_registry_active_retain(NULL) == NULL
		&& route_generation_registry_collect(NULL, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_COLLECT_BAD_ARGUMENT
		&& route_generation_registry_retired(NULL) == NULL, "NULL generation registry accessors were not defensive");
	CHECK(route_generation_registry_completion_observe(NULL, &completion, generation_registry_supervisor(), &now) == ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT
		&& route_generation_registry_completion_observe(registry, NULL, generation_registry_supervisor(), &now) == ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT
		&& route_generation_registry_completion_observe(registry, &completion, NULL, &now) == ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT
		&& route_generation_registry_completion_observe(registry, &completion, generation_registry_supervisor(), NULL) == ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT,
		"invalid generation completion observation was accepted");
	CHECK(route_generation_registry_collect(registry, generation_registry_supervisor(), &invalid_time) == ROUTE_GENERATION_REGISTRY_COLLECT_TIME
		&& route_generation_registry_completion_observe(registry, &completion, generation_registry_supervisor(), &invalid_time) == ROUTE_RESOLUTION_COMPLETION_TIME,
		"invalid generation registry time was accepted");
	route_generation *candidate = generation_fixture_get(0);
	CHECK(route_generation_registry_publish(NULL, &candidate, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_PUBLISH_BAD_ARGUMENT
		&& route_generation_registry_publish(registry, NULL, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_PUBLISH_BAD_ARGUMENT
		&& route_generation_registry_publish(registry, &candidate, NULL, &now) == ROUTE_GENERATION_REGISTRY_PUBLISH_BAD_ARGUMENT
		&& candidate == generation_fixture_get(0), "invalid generation publication was accepted");
	generation_fixtures[0].identity = 0;
	CHECK(route_generation_registry_publish(registry, &candidate, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_PUBLISH_BAD_ARGUMENT
		&& candidate == generation_fixture_get(0),
		"zero-identity candidate generation was accepted");
	generation_fixtures[0].identity = 1;
	CHECK(route_generation_registry_publish(registry, &candidate, generation_registry_supervisor(), &invalid_time) == ROUTE_GENERATION_REGISTRY_PUBLISH_TIME
		&& candidate == generation_fixture_get(0), "invalid publication time transferred candidate ownership");
	generation_fixtures[0].reference_count = 2;
	CHECK(route_generation_registry_publish(registry, &candidate, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_PUBLISH_BAD_ARGUMENT
		&& candidate == generation_fixture_get(0),
		"shared candidate generation was accepted");
	CHECK(route_generation_registry_completion_observe(registry, &completion, generation_registry_supervisor(), &now) == ROUTE_RESOLUTION_COMPLETION_IGNORED,
		"empty generation registry did not ignore a completion");
	route_generation_registry_destroy(NULL);
	route_generation_registry_dispose_in_child(NULL);
	test_result = true;

cleanup:
	route_generation_registry_destroy(registry);
	return test_result;
}

static bool generation_registry_test_collect(void) {
	bool test_result = false;
	route_generation_registry *registry = route_generation_registry_create();
	struct timespec now = { .tv_sec = 10, .tv_nsec = 20 };
	CHECK(registry != NULL, "collect-test generation registry could not be created");
	generation_fixtures_reset();
	CHECK(route_generation_registry_collect(registry, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_COLLECT_NONE,
		"empty generation registry did not report NONE");
	route_generation *first = generation_fixture_get(0);
	route_generation *second = generation_fixture_get(1);
	CHECK(route_generation_registry_publish(registry, &first, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_PUBLISH_OK
		&& first == NULL && route_generation_registry_active_retain(registry) == generation_fixture_get(0)
		&& route_generation_registry_publish(registry, &second, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_PUBLISH_OK
		&& second == NULL, "collect-test generations could not be published");
	CHECK(route_generation_registry_collect(registry, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_COLLECT_RETAINED
		&& generation_fixtures[0].background_release_count == 0 && generation_fixtures[0].reference_count == 2,
		"pinned retired generation was not reported as RETAINED");
	generation_fixtures[0].reference_count = 0;
	CHECK(route_generation_registry_collect(registry, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_COLLECT_BAD_ARGUMENT
		&& generation_fixtures[0].background_release_count == 0, "zero-reference retired generation was reported as retained");
	generation_fixtures[0].reference_count = 2;
	CHECK(route_generation_release(generation_fixture_get(0)) == 1, "collect-test external generation pin was not released");
	generation_fixtures[0].background_release_status = TEST_RESOLUTION_IO;
	CHECK(route_generation_registry_collect(registry, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_COLLECT_IO
		&& generation_fixtures[0].background_release_count == 1 && generation_fixtures[0].reference_count == 1,
		"background-release IO was not propagated or released the generation prematurely");
	generation_fixtures[0].background_release_status = TEST_RESOLUTION_TIME;
	CHECK(route_generation_registry_collect(registry, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_COLLECT_TIME
		&& generation_fixtures[0].background_release_count == 2 && generation_fixtures[0].reference_count == 1,
		"background-release TIME was not propagated or released the generation prematurely");
	generation_fixtures[0].background_release_status = TEST_RESOLUTION_BAD_ARGUMENT;
	CHECK(route_generation_registry_collect(registry, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_COLLECT_BAD_ARGUMENT
		&& generation_fixtures[0].background_release_count == 3 && generation_fixtures[0].reference_count == 1,
		"background-release BAD_ARGUMENT was not propagated or released the generation prematurely");
	generation_fixtures[0].background_release_status = TEST_RESOLUTION_OK;
	CHECK(route_generation_registry_collect(registry, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_COLLECT_COLLECTED
		&& route_generation_registry_retired(registry) == NULL && generation_fixtures[0].background_release_count == 4
		&& generation_fixtures[0].reference_count == 0 && generation_fixtures[0].release_count == 2,
		"retired generation was not collected after background interests were released");
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
	route_generation *first = generation_fixture_get(0);
	route_generation *second = generation_fixture_get(1);
	CHECK(route_generation_registry_publish(registry, &first, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_PUBLISH_OK
		&& first == NULL
		&& route_generation_registry_active_retain(registry) == generation_fixture_get(0)
		&& route_generation_registry_publish(registry, &second, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_PUBLISH_OK
		&& second == NULL,
		"completion-test generations could not be published");
	generation_fixtures[0].completion_status = ROUTE_RESOLUTION_COMPLETION_OK;
	generation_fixtures[1].completion_status = ROUTE_RESOLUTION_COMPLETION_IGNORED;
	CHECK(route_generation_registry_completion_observe(registry, &completion, generation_registry_supervisor(), &now) == ROUTE_RESOLUTION_COMPLETION_OK
		&& generation_fixtures[0].completion_count == 1 && generation_fixtures[1].completion_count == 1,
		"completion was not offered to both live generations");
	generation_fixtures[0].completion_status = ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT;
	generation_fixtures[1].completion_status = ROUTE_RESOLUTION_COMPLETION_OK;
	CHECK(route_generation_registry_completion_observe(registry, &completion, generation_registry_supervisor(), &now) == ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT
		&& generation_fixtures[0].completion_count == 2 && generation_fixtures[1].completion_count == 2,
		"bad completion status prevented full generation fan-out or was not propagated");
	generation_fixtures[0].completion_status = ROUTE_RESOLUTION_COMPLETION_IO;
	generation_fixtures[1].completion_status = ROUTE_RESOLUTION_COMPLETION_OK;
	CHECK(route_generation_registry_completion_observe(registry, &completion, generation_registry_supervisor(), &now) == ROUTE_RESOLUTION_COMPLETION_IO
		&& generation_fixtures[0].completion_count == 3 && generation_fixtures[1].completion_count == 3,
		"IO completion status prevented full generation fan-out or was not propagated");
	generation_fixtures[0].completion_status = ROUTE_RESOLUTION_COMPLETION_OK;
	generation_fixtures[1].completion_status = ROUTE_RESOLUTION_COMPLETION_TIME;
	CHECK(route_generation_registry_completion_observe(registry, &completion, generation_registry_supervisor(), &now) == ROUTE_RESOLUTION_COMPLETION_TIME
		&& generation_fixtures[0].completion_count == 4 && generation_fixtures[1].completion_count == 4,
		"TIME completion status prevented full generation fan-out or was not propagated");
	route_generation_release(generation_fixture_get(0));
	CHECK(route_generation_registry_collect(registry, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_COLLECT_COLLECTED
		&& generation_fixtures[0].background_release_count == 1, "unpinned completion-test retired generation was not collected");
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
	route_generation *first = generation_fixture_get(0);
	route_generation *second = generation_fixture_get(1);
	CHECK(route_generation_registry_publish(registry, &first, generation_registry_supervisor(), &(struct timespec){ 0 }) == ROUTE_GENERATION_REGISTRY_PUBLISH_OK
		&& first == NULL
		&& route_generation_registry_active_retain(registry) == generation_fixture_get(0)
		&& route_generation_registry_publish(registry, &second, generation_registry_supervisor(), &(struct timespec){ 0 }) == ROUTE_GENERATION_REGISTRY_PUBLISH_OK
		&& second == NULL,
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
	struct timespec now = { .tv_sec = 1, .tv_nsec = 2 };
	CHECK(registry != NULL, "publication-test generation registry could not be created");
	generation_fixtures_reset();
	route_generation *first = generation_fixture_get(0);
	route_generation *second = generation_fixture_get(1);
	route_generation *third = generation_fixture_get(2);
	CHECK(route_generation_registry_publish(registry, &first, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_PUBLISH_OK && first == NULL
		&& route_generation_registry_active(registry) == generation_fixture_get(0)
		&& route_generation_registry_retired(registry) == NULL, "initial generation publication was incorrect");
	CHECK(route_generation_registry_active_retain(registry) == generation_fixture_get(0) && generation_fixtures[0].reference_count == 2 && generation_fixtures[0].retain_count == 1,
		"active generation could not be pinned");
	CHECK(route_generation_registry_publish(registry, &second, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_PUBLISH_OK && second == NULL
		&& route_generation_registry_active(registry) == generation_fixture_get(1)
		&& route_generation_registry_retired(registry) == generation_fixture_get(0), "replacement generation did not retain the pinned active generation");
	CHECK(route_generation_registry_publish(registry, &third, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_PUBLISH_BLOCKED && third == generation_fixture_get(2)
		&& route_generation_registry_active(registry) == generation_fixture_get(1)
		&& route_generation_registry_retired(registry) == generation_fixture_get(0) && generation_fixtures[2].reference_count == 1, "third generation bypassed the live-generation bound");
	CHECK(route_generation_release(generation_fixture_get(0)) == 1
		&& route_generation_registry_collect(registry, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_COLLECT_COLLECTED
		&& route_generation_registry_retired(registry) == NULL
		&& generation_fixtures[0].reference_count == 0 && generation_fixtures[0].release_count == 2, "retired generation was not collected after its final external release");
	CHECK(route_generation_registry_publish(registry, &third, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_PUBLISH_OK && third == NULL
		&& route_generation_registry_active(registry) == generation_fixture_get(2)
		&& route_generation_registry_retired(registry) == NULL && generation_fixtures[1].reference_count == 0,
		"third generation was not published after retired collection or unpinned active generation was retained");
	generation_fixtures[1].identity = 4;
	generation_fixtures[1].reference_count = 1;
	second = generation_fixture_get(1);
	CHECK(route_generation_registry_publish(registry, &second, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_PUBLISH_OK && second == NULL
		&& route_generation_registry_active(registry) == generation_fixture_get(1),
		"newer generation identity was rejected");
	generation_fixtures[0].identity = 4;
	generation_fixtures[0].reference_count = 1;
	first = generation_fixture_get(0);
	CHECK(route_generation_registry_publish(registry, &first, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_PUBLISH_BAD_ARGUMENT && first == generation_fixture_get(0),
		"non-increasing generation identity was accepted");
	test_result = true;

cleanup:
	route_generation_registry_destroy(registry);
	return test_result;
}

static bool generation_registry_test_publish_errors(void) {
	bool test_result = false;
	struct timespec now = { .tv_sec = 1, .tv_nsec = 2 };
	route_generation_registry *registry = route_generation_registry_create();
	CHECK(registry != NULL, "publish-error generation registry could not be created");
	generation_fixtures_reset();
	route_generation *first = generation_fixture_get(0);
	route_generation *second = generation_fixture_get(1);
	route_generation *third = generation_fixture_get(2);
	CHECK(route_generation_registry_publish(registry, &first, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_PUBLISH_OK
		&& first == NULL && route_generation_registry_active_retain(registry) == generation_fixture_get(0)
		&& route_generation_registry_publish(registry, &second, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_PUBLISH_OK && second == NULL,
		"publish-error generations could not establish a pinned retired generation");
	CHECK(route_generation_registry_publish(registry, &third, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_PUBLISH_BLOCKED
		&& third == generation_fixture_get(2), "pre-swap RETAINED did not block or transferred candidate");
	CHECK(route_generation_release(generation_fixture_get(0)) == 1, "publish-error external generation pin was not released");
	generation_fixtures[0].background_release_status = TEST_RESOLUTION_IO;
	CHECK(route_generation_registry_publish(registry, &third, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_PUBLISH_IO
		&& third == generation_fixture_get(2) && route_generation_registry_active(registry) == generation_fixture_get(1)
		&& route_generation_registry_retired(registry) == generation_fixture_get(0) && generation_fixtures[0].reference_count == 1,
		"pre-swap background-release IO did not preserve candidate ownership");
	generation_fixtures[0].background_release_status = TEST_RESOLUTION_OK;
	CHECK(route_generation_registry_publish(registry, &third, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_PUBLISH_OK
		&& third == NULL && route_generation_registry_active(registry) == generation_fixture_get(2)
		&& route_generation_registry_retired(registry) == NULL, "candidate was not published after pre-swap recovery");
	route_generation_registry_destroy(registry);
	registry = NULL;
	generation_fixtures_reset();
	first = generation_fixture_get(0);
	second = generation_fixture_get(1);
	CHECK((registry = route_generation_registry_create()) != NULL
		&& route_generation_registry_publish(registry, &first, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_PUBLISH_OK && first == NULL,
		"post-swap-error registry could not publish initial generation");
	generation_fixtures[0].background_release_status = TEST_RESOLUTION_IO;
	CHECK(route_generation_registry_publish(registry, &second, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_PUBLISH_IO
		&& second == NULL && route_generation_registry_active(registry) == generation_fixture_get(1)
		&& route_generation_registry_retired(registry) == generation_fixture_get(0) && generation_fixtures[0].reference_count == 1,
		"post-swap background-release IO did not preserve committed registry ownership");
	generation_fixtures[0].background_release_status = TEST_RESOLUTION_OK;
	CHECK(route_generation_registry_collect(registry, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_COLLECT_COLLECTED
		&& route_generation_registry_retired(registry) == NULL, "post-swap-error retired generation was not locally recoverable");
	route_generation_registry_destroy(registry);
	registry = NULL;
	generation_fixtures_reset();
	first = generation_fixture_get(0);
	second = generation_fixture_get(1);
	CHECK((registry = route_generation_registry_create()) != NULL
		&& route_generation_registry_publish(registry, &first, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_PUBLISH_OK && first == NULL,
		"post-swap-time registry could not publish initial generation");
	generation_fixtures[0].background_release_status = TEST_RESOLUTION_TIME;
	CHECK(route_generation_registry_publish(registry, &second, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_PUBLISH_TIME
		&& second == NULL && route_generation_registry_active(registry) == generation_fixture_get(1)
		&& route_generation_registry_retired(registry) == generation_fixture_get(0) && generation_fixtures[0].reference_count == 1,
		"post-swap background-release TIME did not preserve committed registry ownership");
	generation_fixtures[0].background_release_status = TEST_RESOLUTION_OK;
	CHECK(route_generation_registry_collect(registry, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_COLLECT_COLLECTED
		&& route_generation_registry_retired(registry) == NULL, "post-swap-TIME retired generation was not locally recoverable");
	route_generation_registry_destroy(registry);
	registry = NULL;
	generation_fixtures_reset();
	first = generation_fixture_get(0);
	second = generation_fixture_get(1);
	CHECK((registry = route_generation_registry_create()) != NULL
		&& route_generation_registry_publish(registry, &first, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_PUBLISH_OK && first == NULL,
		"post-swap-bad-argument registry could not publish initial generation");
	generation_fixtures[0].background_release_status = TEST_RESOLUTION_BAD_ARGUMENT;
	CHECK(route_generation_registry_publish(registry, &second, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_PUBLISH_BAD_ARGUMENT
		&& second == NULL && route_generation_registry_active(registry) == generation_fixture_get(1)
		&& route_generation_registry_retired(registry) == generation_fixture_get(0) && generation_fixtures[0].reference_count == 1,
		"post-swap background-release BAD_ARGUMENT did not preserve committed registry ownership");
	generation_fixtures[0].background_release_status = TEST_RESOLUTION_OK;
	CHECK(route_generation_registry_collect(registry, generation_registry_supervisor(), &now) == ROUTE_GENERATION_REGISTRY_COLLECT_COLLECTED
		&& route_generation_registry_retired(registry) == NULL, "post-swap-BAD_ARGUMENT retired generation was not locally recoverable");
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

route_resolution_completion_status __wrap_route_resolution_completion_observe_with_supervisor(route_resolution *resolution, resolver_supervisor *supervisor,
	const resolver_supervisor_completion *completion, const struct timespec *now) {
	generation_registry_fixture *fixture = generation_fixture_find_resolution(resolution);
	if (fixture == NULL || completion == NULL || supervisor == NULL || now == NULL) {
		return ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT;
	}
	fixture->completion_count++;
	return fixture->completion_status;
}

route_resolution_release_status __wrap_route_resolution_background_release(route_resolution *resolution, resolver_supervisor *supervisor, const struct timespec *now) {
	generation_registry_fixture *fixture = generation_fixture_find_resolution(resolution);
	if (fixture == NULL || supervisor == NULL || now == NULL) {
		return ROUTE_RESOLUTION_RELEASE_BAD_ARGUMENT;
	}
	fixture->background_release_count++;
	switch (fixture->background_release_status) {
		case TEST_RESOLUTION_OK:
			return ROUTE_RESOLUTION_RELEASE_OK;
		case TEST_RESOLUTION_IO:
			return ROUTE_RESOLUTION_RELEASE_IO;
		case TEST_RESOLUTION_TIME:
			return ROUTE_RESOLUTION_RELEASE_TIME;
		case TEST_RESOLUTION_BAD_ARGUMENT:
		default:
			return ROUTE_RESOLUTION_RELEASE_BAD_ARGUMENT;
	}
}

/* section: functions (entry point) */
int main(void) {
	if (!generation_registry_test_arguments() || !generation_registry_test_collect() || !generation_registry_test_completion()
		|| !generation_registry_test_dispose_in_child() || !generation_registry_test_publication() || !generation_registry_test_publish_errors()) {
		return 1;
	}
	return 0;
}
