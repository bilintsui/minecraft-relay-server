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
#include "../timeutil.h"
#include "generation.h"
#include "resolution.h"

/* section: headers (self) */
#include "generation_registry.h"

/* section: types */
struct route_generation_registry {
	route_generation *active;
	route_generation *retired;
};

/* section: functions (local) */
static route_resolution_completion_status route_generation_registry_completion_status_merge(route_resolution_completion_status current,
	route_resolution_completion_status update) {
	if (current == ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT || current == ROUTE_RESOLUTION_COMPLETION_IO || current == ROUTE_RESOLUTION_COMPLETION_TIME) {
		return current;
	}
	if (update == ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT || update == ROUTE_RESOLUTION_COMPLETION_IO || update == ROUTE_RESOLUTION_COMPLETION_TIME) {
		return update;
	}
	return update == ROUTE_RESOLUTION_COMPLETION_OK ? ROUTE_RESOLUTION_COMPLETION_OK : current;
}

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

route_generation_registry_collect_status route_generation_registry_collect(route_generation_registry *registry, resolver_supervisor *supervisor, const struct timespec *now) {
	if (registry == NULL || supervisor == NULL || now == NULL) {
		return ROUTE_GENERATION_REGISTRY_COLLECT_BAD_ARGUMENT;
	}
	if (!timeutil_valid(now)) {
		return ROUTE_GENERATION_REGISTRY_COLLECT_TIME;
	}
	if (registry->retired == NULL) {
		return ROUTE_GENERATION_REGISTRY_COLLECT_NONE;
	}
	size_t reference_count = route_generation_reference_count(registry->retired);
	if (reference_count == 0) {
		return ROUTE_GENERATION_REGISTRY_COLLECT_BAD_ARGUMENT;
	}
	if (reference_count > 1) {
		return ROUTE_GENERATION_REGISTRY_COLLECT_RETAINED;
	}
	route_resolution_release_status status = route_resolution_background_release(route_generation_resolution(registry->retired), supervisor, now);
	switch (status) {
		case ROUTE_RESOLUTION_RELEASE_OK:
			break;
		case ROUTE_RESOLUTION_RELEASE_BAD_ARGUMENT:
			return ROUTE_GENERATION_REGISTRY_COLLECT_BAD_ARGUMENT;
		case ROUTE_RESOLUTION_RELEASE_IO:
			return ROUTE_GENERATION_REGISTRY_COLLECT_IO;
		case ROUTE_RESOLUTION_RELEASE_TIME:
			return ROUTE_GENERATION_REGISTRY_COLLECT_TIME;
		default:
			return ROUTE_GENERATION_REGISTRY_COLLECT_BAD_ARGUMENT;
	}
	if (route_generation_release(registry->retired) != 0) {
		return ROUTE_GENERATION_REGISTRY_COLLECT_BAD_ARGUMENT;
	}
	registry->retired = NULL;
	return ROUTE_GENERATION_REGISTRY_COLLECT_COLLECTED;
}

route_resolution_completion_status route_generation_registry_completion_observe(route_generation_registry *registry, const resolver_supervisor_completion *completion,
	resolver_supervisor *supervisor, const struct timespec *now) {
	if (registry == NULL || completion == NULL || supervisor == NULL || now == NULL) {
		return ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT;
	}
	if (!timeutil_valid(now)) {
		return ROUTE_RESOLUTION_COMPLETION_TIME;
	}
	route_resolution_completion_status result = ROUTE_RESOLUTION_COMPLETION_IGNORED;
	route_generation *generations[] = { registry->active, registry->retired };
	for (size_t generation_index = 0; generation_index < sizeof(generations) / sizeof(generations[0]); generation_index++) {
		if (generations[generation_index] == NULL) {
			continue;
		}
		route_resolution_completion_status status = route_resolution_completion_observe_with_supervisor(route_generation_resolution(generations[generation_index]), supervisor, completion, now);
		result = route_generation_registry_completion_status_merge(result, status);
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

route_generation_registry_publish_status route_generation_registry_publish(route_generation_registry *registry, route_generation **candidate, resolver_supervisor *supervisor,
	const struct timespec *now) {
	if (registry == NULL || candidate == NULL || *candidate == NULL || supervisor == NULL || now == NULL || route_generation_identity(*candidate) == 0
		|| route_generation_reference_count(*candidate) != 1 || (registry->active != NULL && route_generation_identity(*candidate) <= route_generation_identity(registry->active))) {
		return ROUTE_GENERATION_REGISTRY_PUBLISH_BAD_ARGUMENT;
	}
	route_generation_registry_collect_status collect_status = route_generation_registry_collect(registry, supervisor, now);
	switch (collect_status) {
		case ROUTE_GENERATION_REGISTRY_COLLECT_NONE:
		case ROUTE_GENERATION_REGISTRY_COLLECT_COLLECTED:
			break;
		case ROUTE_GENERATION_REGISTRY_COLLECT_RETAINED:
			return ROUTE_GENERATION_REGISTRY_PUBLISH_BLOCKED;
		case ROUTE_GENERATION_REGISTRY_COLLECT_IO:
			return ROUTE_GENERATION_REGISTRY_PUBLISH_IO;
		case ROUTE_GENERATION_REGISTRY_COLLECT_TIME:
			return ROUTE_GENERATION_REGISTRY_PUBLISH_TIME;
		case ROUTE_GENERATION_REGISTRY_COLLECT_BAD_ARGUMENT:
		default:
			return ROUTE_GENERATION_REGISTRY_PUBLISH_BAD_ARGUMENT;
	}
	registry->retired = registry->active;
	registry->active = *candidate;
	*candidate = NULL;
	collect_status = route_generation_registry_collect(registry, supervisor, now);
	switch (collect_status) {
		case ROUTE_GENERATION_REGISTRY_COLLECT_NONE:
		case ROUTE_GENERATION_REGISTRY_COLLECT_RETAINED:
		case ROUTE_GENERATION_REGISTRY_COLLECT_COLLECTED:
			return ROUTE_GENERATION_REGISTRY_PUBLISH_OK;
		case ROUTE_GENERATION_REGISTRY_COLLECT_IO:
			return ROUTE_GENERATION_REGISTRY_PUBLISH_IO;
		case ROUTE_GENERATION_REGISTRY_COLLECT_TIME:
			return ROUTE_GENERATION_REGISTRY_PUBLISH_TIME;
		case ROUTE_GENERATION_REGISTRY_COLLECT_BAD_ARGUMENT:
		default:
			return ROUTE_GENERATION_REGISTRY_PUBLISH_BAD_ARGUMENT;
	}
}

route_generation *route_generation_registry_retired(const route_generation_registry *registry) {
	return registry == NULL ? NULL : registry->retired;
}
