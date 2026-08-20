/*
 * route_generation.c: Tests for prepared listener route generation ownership
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

/* section: headers (project) */
#include "config.h"
#include "hosts.h"
#include "route_bindings.h"
#include "route_generation.h"
#include "route_resolution.h"
#include "route_table.h"

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
typedef enum {
	GENERATION_DESTROY_RESOLUTION,
	GENERATION_DESTROY_BINDINGS,
	GENERATION_DESTROY_ROUTES,
	GENERATION_DESTROY_HOSTS,
	GENERATION_DESTROY_CONFIG
} generation_destroy_kind;
typedef struct {
	route_bindings *bindings;
	conf *config;
	hosts_table *hosts;
	route_resolution *resolution;
	route_table *routes;
} generation_fixture;

/* section: global variables */
static size_t generation_destroy_count;
static generation_destroy_kind generation_destroy_kinds[5];
static generation_fixture generation_expected;

/* section: functions (local) */
static void generation_destroy_observe(generation_destroy_kind kind) {
	if (generation_destroy_count < sizeof(generation_destroy_kinds) / sizeof(generation_destroy_kinds[0])) {
		generation_destroy_kinds[generation_destroy_count] = kind;
	}
	generation_destroy_count++;
}

static generation_fixture generation_fixture_create(void) {
	static unsigned char binding_storage;
	static unsigned char config_storage;
	static unsigned char hosts_storage;
	static unsigned char resolution_storage;
	static unsigned char routes_storage;
	return (generation_fixture){
		.bindings = (route_bindings *)&binding_storage,
		.config = (conf *)&config_storage,
		.hosts = (hosts_table *)&hosts_storage,
		.resolution = (route_resolution *)&resolution_storage,
		.routes = (route_table *)&routes_storage
	};
}

static void generation_fixture_reset(const generation_fixture *fixture) {
	generation_destroy_count = 0;
	memset(generation_destroy_kinds, 0, sizeof(generation_destroy_kinds));
	generation_expected = *fixture;
}

static bool generation_test_arguments(void) {
	bool test_result = false;
	generation_fixture fixture = generation_fixture_create();
	route_generation *generation = NULL;
	CHECK(route_generation_create(0, fixture.config, fixture.hosts, fixture.routes, fixture.bindings, fixture.resolution, &generation) == ROUTE_GENERATION_CREATE_BAD_ARGUMENT,
		"zero generation identity was accepted");
	CHECK(route_generation_create(1, NULL, fixture.hosts, fixture.routes, fixture.bindings, fixture.resolution, &generation) == ROUTE_GENERATION_CREATE_BAD_ARGUMENT,
		"NULL generation config was accepted");
	CHECK(route_generation_create(1, fixture.config, NULL, fixture.routes, fixture.bindings, fixture.resolution, &generation) == ROUTE_GENERATION_CREATE_BAD_ARGUMENT,
		"NULL generation hosts table was accepted");
	CHECK(route_generation_create(1, fixture.config, fixture.hosts, NULL, fixture.bindings, fixture.resolution, &generation) == ROUTE_GENERATION_CREATE_BAD_ARGUMENT,
		"NULL generation route table was accepted");
	CHECK(route_generation_create(1, fixture.config, fixture.hosts, fixture.routes, NULL, fixture.resolution, &generation) == ROUTE_GENERATION_CREATE_BAD_ARGUMENT,
		"NULL generation bindings were accepted");
	CHECK(route_generation_create(1, fixture.config, fixture.hosts, fixture.routes, fixture.bindings, NULL, &generation) == ROUTE_GENERATION_CREATE_BAD_ARGUMENT,
		"NULL generation resolution was accepted");
	CHECK(route_generation_create(1, fixture.config, fixture.hosts, fixture.routes, fixture.bindings, fixture.resolution, NULL) == ROUTE_GENERATION_CREATE_BAD_ARGUMENT,
		"NULL generation output was accepted");
	generation = (route_generation *)(uintptr_t)1;
	CHECK(route_generation_create(1, fixture.config, fixture.hosts, fixture.routes, fixture.bindings, fixture.resolution, &generation) == ROUTE_GENERATION_CREATE_BAD_ARGUMENT,
		"non-empty generation output was accepted");
	CHECK(route_generation_bindings(NULL) == NULL && route_generation_config(NULL) == NULL && route_generation_hosts(NULL) == NULL && route_generation_identity(NULL) == 0
		&& route_generation_reference_count(NULL) == 0 && route_generation_release(NULL) == 0 && route_generation_resolution(NULL) == NULL && !route_generation_retain(NULL)
		&& route_generation_routes(NULL) == NULL, "NULL generation accessors were not defensive");
	CHECK(generation_destroy_count == 0, "invalid generation creation consumed caller-owned components");
	test_result = true;

cleanup:
	return test_result;
}

static bool generation_test_dispose_in_child(void) {
	bool test_result = false;
	generation_fixture fixture = generation_fixture_create();
	route_generation *generation = NULL;
	generation_fixture_reset(&fixture);
	CHECK(route_generation_create(8, fixture.config, fixture.hosts, fixture.routes, fixture.bindings, fixture.resolution, &generation) == ROUTE_GENERATION_CREATE_OK,
		"child-dispose generation could not be created");
	CHECK(route_generation_retain(generation) && route_generation_retain(generation) && route_generation_reference_count(generation) == 3,
		"child-dispose generation references could not be prepared");
	route_generation_dispose_in_child(generation);
	generation = NULL;
	CHECK(generation_destroy_count == 5, "child dispose honored the inherited reference count");
	test_result = true;

cleanup:
	if (generation != NULL) {
		route_generation_dispose_in_child(generation);
	}
	return test_result;
}

static bool generation_test_lifecycle(void) {
	static const generation_destroy_kind expected_order[] = {
		GENERATION_DESTROY_RESOLUTION,
		GENERATION_DESTROY_BINDINGS,
		GENERATION_DESTROY_ROUTES,
		GENERATION_DESTROY_HOSTS,
		GENERATION_DESTROY_CONFIG
	};
	bool test_result = false;
	generation_fixture fixture = generation_fixture_create();
	route_generation *generation = NULL;
	generation_fixture_reset(&fixture);
	CHECK(route_generation_create(42, fixture.config, fixture.hosts, fixture.routes, fixture.bindings, fixture.resolution, &generation) == ROUTE_GENERATION_CREATE_OK,
		"generation could not be created");
	CHECK(route_generation_bindings(generation) == fixture.bindings && route_generation_config(generation) == fixture.config && route_generation_hosts(generation) == fixture.hosts
		&& route_generation_identity(generation) == 42 && route_generation_reference_count(generation) == 1 && route_generation_resolution(generation) == fixture.resolution
		&& route_generation_routes(generation) == fixture.routes, "generation accessors did not preserve owned components");
	CHECK(route_generation_retain(generation) && route_generation_retain(generation) && route_generation_reference_count(generation) == 3,
		"generation references could not be retained");
	CHECK(route_generation_release(generation) == 2 && route_generation_release(generation) == 1 && generation_destroy_count == 0,
		"generation was destroyed while references remained");
	CHECK(route_generation_release(generation) == 0, "final generation release returned a nonzero count");
	generation = NULL;
	CHECK(generation_destroy_count == sizeof(expected_order) / sizeof(expected_order[0])
		&& memcmp(generation_destroy_kinds, expected_order, sizeof(expected_order)) == 0, "generation components were not destroyed once in dependency order");
	test_result = true;

cleanup:
	if (generation != NULL) {
		route_generation_dispose_in_child(generation);
	}
	return test_result;
}

/* section: functions (exported) */
void __wrap_config_destroy(conf *target) {
	if (target != generation_expected.config) {
		generation_destroy_count = SIZE_MAX;
		return;
	}
	generation_destroy_observe(GENERATION_DESTROY_CONFIG);
}

void __wrap_hosts_table_destroy(hosts_table *table) {
	if (table != generation_expected.hosts) {
		generation_destroy_count = SIZE_MAX;
		return;
	}
	generation_destroy_observe(GENERATION_DESTROY_HOSTS);
}

void __wrap_route_bindings_destroy(route_bindings *bindings) {
	if (bindings != generation_expected.bindings) {
		generation_destroy_count = SIZE_MAX;
		return;
	}
	generation_destroy_observe(GENERATION_DESTROY_BINDINGS);
}

void __wrap_route_resolution_destroy(route_resolution *resolution) {
	if (resolution != generation_expected.resolution) {
		generation_destroy_count = SIZE_MAX;
		return;
	}
	generation_destroy_observe(GENERATION_DESTROY_RESOLUTION);
}

void __wrap_route_table_destroy(route_table *table) {
	if (table != generation_expected.routes) {
		generation_destroy_count = SIZE_MAX;
		return;
	}
	generation_destroy_observe(GENERATION_DESTROY_ROUTES);
}

/* section: functions (entry point) */
int main(void) {
	if (!generation_test_arguments() || !generation_test_dispose_in_child() || !generation_test_lifecycle()) {
		return 1;
	}
	return 0;
}
