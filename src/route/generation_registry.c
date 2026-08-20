/*
 * route/generation_registry.c: Bounded live listener route generations
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>

/* section: headers (project) */
#include "../resolver/supervisor.h"
#include "generation.h"
#include "resolution.h"

/* section: headers (self) */
#include "generation_registry.h"

/* section: types */
struct route_generation_registry {
	route_generation *active;
	route_generation *retired;
};

/* section: functions (exported) */
route_generation *route_generation_registry_active(const route_generation_registry *registry) {
	return registry == NULL ? NULL : registry->active;
}

route_generation *route_generation_registry_active_retain(route_generation_registry *registry) {
	if (registry == NULL || !route_generation_retain(registry->active)) {
		return NULL;
	}
	return registry->active;
}

bool route_generation_registry_collect(route_generation_registry *registry) {
	if (registry == NULL || registry->retired == NULL || route_generation_reference_count(registry->retired) != 1) {
		return false;
	}
	route_generation_release(registry->retired);
	registry->retired = NULL;
	return true;
}

route_resolution_completion_status route_generation_registry_completion_observe(route_generation_registry *registry, const resolver_supervisor_completion *completion,
	const struct timespec *now) {
	if (registry == NULL || completion == NULL || now == NULL) {
		return ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT;
	}
	route_resolution_completion_status result = ROUTE_RESOLUTION_COMPLETION_IGNORED;
	route_generation *generations[] = { registry->active, registry->retired };
	for (size_t generation_index = 0; generation_index < sizeof(generations) / sizeof(generations[0]); generation_index++) {
		if (generations[generation_index] == NULL) {
			continue;
		}
		route_resolution_completion_status status = route_resolution_completion_observe(route_generation_resolution(generations[generation_index]), completion, now);
		if (status == ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT) {
			result = ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT;
		} else if (status == ROUTE_RESOLUTION_COMPLETION_OK && result == ROUTE_RESOLUTION_COMPLETION_IGNORED) {
			result = ROUTE_RESOLUTION_COMPLETION_OK;
		}
	}
	return result;
}

route_generation_registry *route_generation_registry_create(void) {
	return calloc(1, sizeof(route_generation_registry));
}

void route_generation_registry_destroy(route_generation_registry *registry) {
	if (registry == NULL) {
		return;
	}
	route_generation_release(registry->active);
	route_generation_release(registry->retired);
	free(registry);
}

void route_generation_registry_dispose_in_child(route_generation_registry *registry) {
	if (registry == NULL) {
		return;
	}
	route_generation_dispose_in_child(registry->active);
	route_generation_dispose_in_child(registry->retired);
	free(registry);
}

route_generation_registry_publish_status route_generation_registry_publish(route_generation_registry *registry, route_generation *candidate) {
	if (registry == NULL || candidate == NULL || route_generation_identity(candidate) == 0 || route_generation_reference_count(candidate) != 1
		|| (registry->active != NULL && route_generation_identity(candidate) <= route_generation_identity(registry->active))) {
		return ROUTE_GENERATION_REGISTRY_PUBLISH_BAD_ARGUMENT;
	}
	route_generation_registry_collect(registry);
	if (registry->retired != NULL) {
		return ROUTE_GENERATION_REGISTRY_PUBLISH_BLOCKED;
	}
	registry->retired = registry->active;
	registry->active = candidate;
	route_generation_registry_collect(registry);
	return ROUTE_GENERATION_REGISTRY_PUBLISH_OK;
}

route_generation *route_generation_registry_retired(const route_generation_registry *registry) {
	return registry == NULL ? NULL : registry->retired;
}
