/*
 * route_generation.c: Reference-counted prepared listener route generation
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/* section: headers (project) */
#include "config.h"
#include "hosts.h"
#include "route_bindings.h"
#include "route_resolution.h"
#include "route_table.h"

/* section: headers (self) */
#include "route_generation.h"

/* section: types */
struct route_generation {
	route_bindings *bindings;
	conf *config;
	hosts_table *hosts;
	uint64_t identity;
	size_t reference_count;
	route_resolution *resolution;
	route_table *routes;
};

/* section: functions (local) */
static void route_generation_resources_destroy(route_generation *generation) {
	if (generation == NULL) {
		return;
	}
	route_resolution_destroy(generation->resolution);
	route_bindings_destroy(generation->bindings);
	route_table_destroy(generation->routes);
	hosts_table_destroy(generation->hosts);
	config_destroy(generation->config);
	free(generation);
}

/* section: functions (exported) */
const route_bindings *route_generation_bindings(const route_generation *generation) {
	return generation == NULL ? NULL : generation->bindings;
}

const conf *route_generation_config(const route_generation *generation) {
	return generation == NULL ? NULL : generation->config;
}

route_generation_create_status route_generation_create(uint64_t identity, conf *config, hosts_table *hosts, route_table *routes, route_bindings *bindings,
	route_resolution *resolution, route_generation **result) {
	if (identity == 0 || config == NULL || hosts == NULL || bindings == NULL || resolution == NULL || routes == NULL || result == NULL || *result != NULL) {
		return ROUTE_GENERATION_CREATE_BAD_ARGUMENT;
	}
	route_generation *generation = calloc(1, sizeof(*generation));
	if (generation == NULL) {
		return ROUTE_GENERATION_CREATE_MEMORY;
	}
	generation->bindings = bindings;
	generation->config = config;
	generation->hosts = hosts;
	generation->identity = identity;
	generation->reference_count = 1;
	generation->resolution = resolution;
	generation->routes = routes;
	*result = generation;
	return ROUTE_GENERATION_CREATE_OK;
}

void route_generation_dispose_in_child(route_generation *generation) {
	route_generation_resources_destroy(generation);
}

const hosts_table *route_generation_hosts(const route_generation *generation) {
	return generation == NULL ? NULL : generation->hosts;
}

uint64_t route_generation_identity(const route_generation *generation) {
	return generation == NULL ? 0 : generation->identity;
}

size_t route_generation_reference_count(const route_generation *generation) {
	return generation == NULL ? 0 : generation->reference_count;
}

size_t route_generation_release(route_generation *generation) {
	if (generation == NULL || generation->reference_count == 0) {
		return 0;
	}
	generation->reference_count--;
	if (generation->reference_count == 0) {
		route_generation_resources_destroy(generation);
		return 0;
	}
	return generation->reference_count;
}

route_resolution *route_generation_resolution(route_generation *generation) {
	return generation == NULL ? NULL : generation->resolution;
}

bool route_generation_retain(route_generation *generation) {
	if (generation == NULL || generation->reference_count == SIZE_MAX) {
		return false;
	}
	generation->reference_count++;
	return true;
}

const route_table *route_generation_routes(const route_generation *generation) {
	return generation == NULL ? NULL : generation->routes;
}
