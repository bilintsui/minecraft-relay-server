/*
 * listener/generation.c: Listener route generation preparation, publication and ownership
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/* section: headers (project) */
#include "../log.h"
#include "../route/generation.h"
#include "../route/generation_registry.h"
#include "context.h"

/* section: headers (self) */
#include "generation.h"

/* section: functions (local) */
static void listener_generation_active_set(listener_context *context, route_generation *active) {
	context->config = (conf *)route_generation_config(active);
	context->hosts = (hosts_table *)route_generation_hosts(active);
	context->route_bindings = (route_bindings *)route_generation_bindings(active);
	context->route_resolution = route_generation_resolution(active);
	context->routes = (route_table *)route_generation_routes(active);
}

static bool listener_generation_create(listener_context *context, conf *config, hosts_table *hosts, route_table *routes, route_bindings *bindings,
	route_resolution *resolution, mksys_level failure_level, const char *failure_action, route_generation **result) {
	if (result == NULL || *result != NULL) {
		return false;
	}
	route_generation_create_status status = route_generation_create(context->generation_next_identity, config, hosts, routes, bindings, resolution, result);
	if (status == ROUTE_GENERATION_CREATE_OK) {
		return true;
	}
	LISTENER_LOG(context, failure_level,
		"Cannot own prepared proxy route generation: %s%s.",
		status == ROUTE_GENERATION_CREATE_MEMORY ? "memory allocation failed" : "invalid internal generation state", failure_action
	);
	return false;
}

static const char *listener_hosts_load_error(hosts_load_status status) {
	switch (status) {
		case HOSTS_LOAD_LIMIT:
			return "entry limit reached";
		case HOSTS_LOAD_MEMORY:
			return "memory allocation failed";
		case HOSTS_LOAD_BAD_ARGUMENT:
		default:
			return "invalid loader state";
	}
}

static bool listener_route_bindings_prepare(listener_context *context, const route_table *routes, const hosts_table *hosts, mksys_level failure_level, const char *failure_action, route_bindings **result) {
	route_bindings_build_status status = route_bindings_build(routes, hosts, context->dns_cache, result);
	if (status == ROUTE_BINDINGS_BUILD_OK) {
		return true;
	}
	const char *reason;
	switch (status) {
		case ROUTE_BINDINGS_BUILD_LIMIT:
			reason = "resolver cache capacity reached";
			break;
		case ROUTE_BINDINGS_BUILD_MEMORY:
			reason = "memory allocation failed";
			break;
		case ROUTE_BINDINGS_BUILD_BAD_ARGUMENT:
		case ROUTE_BINDINGS_BUILD_INVALID:
		default:
			reason = "invalid internal binding state";
			break;
	}
	LISTENER_LOG(context, failure_level, "Cannot prepare proxy resolver bindings: %s%s.", reason, failure_action);
	return false;
}

static listener_route_prepare_status listener_route_resolution_prepare(listener_context *context, const route_bindings *bindings, const hosts_table *hosts,
	mksys_level failure_level, const char *failure_action, route_resolution **result) {
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
		return LISTENER_ROUTE_PREPARE_TIME_ERROR;
	}
	route_resolution_build_status status = route_resolution_build(bindings, hosts, context->dns_cache, &now, result);
	if (status == ROUTE_RESOLUTION_BUILD_OK) {
		return LISTENER_ROUTE_PREPARE_OK;
	}
	const char *reason = status == ROUTE_RESOLUTION_BUILD_MEMORY ? "memory allocation failed" : "invalid internal resolution state";
	LISTENER_LOG(context, failure_level, "Cannot prepare proxy route resolution: %s%s.", reason, failure_action);
	return LISTENER_ROUTE_PREPARE_CANDIDATE_ERROR;
}

/* section: functions (exported) */
bool listener_generation_collect(listener_context *context, const struct timespec *now) {
	route_generation_registry_collect_status status = route_generation_registry_collect(context->generations, context->resolver, now);
	switch (status) {
		case ROUTE_GENERATION_REGISTRY_COLLECT_NONE:
		case ROUTE_GENERATION_REGISTRY_COLLECT_RETAINED:
		case ROUTE_GENERATION_REGISTRY_COLLECT_COLLECTED:
			return true;
		case ROUTE_GENERATION_REGISTRY_COLLECT_IO:
			errno = EIO;
			return false;
		case ROUTE_GENERATION_REGISTRY_COLLECT_TIME:
			errno = EOVERFLOW;
			return false;
		case ROUTE_GENERATION_REGISTRY_COLLECT_BAD_ARGUMENT:
		default:
			errno = EINVAL;
			return false;
	}
}

void listener_generation_destroy(listener_context *context) {
	bool generation_owned = route_generation_registry_active(context->generations) != NULL;
	route_generation_registry_destroy(context->generations);
	if (!generation_owned) {
		route_resolution_destroy(context->route_resolution);
		route_bindings_destroy(context->route_bindings);
		hosts_table_destroy(context->hosts);
		route_table_destroy(context->routes);
		config_destroy(context->config);
	}
}

void listener_generation_dispose_in_child(listener_context *context) {
	route_generation_registry_dispose_in_child(context->generations);
	context->generations = NULL;
	listener_generation_active_set(context, NULL);
}

bool listener_generation_initial_publish(listener_context *context) {
	if (!listener_route_bindings_prepare(context, context->routes, context->hosts, MKSYS_LEVEL_CRITICAL, "", &context->route_bindings)) {
		return false;
	}
	listener_route_prepare_status resolution_status = listener_route_resolution_prepare(context, context->route_bindings, context->hosts, MKSYS_LEVEL_CRITICAL, "", &context->route_resolution);
	if (resolution_status != LISTENER_ROUTE_PREPARE_OK) {
		if (resolution_status == LISTENER_ROUTE_PREPARE_TIME_ERROR) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot sample the monotonic clock while preparing proxy route resolution: %s", strerror(errno));
		}
		return false;
	}
	route_generation *initial_generation = NULL;
	if (!listener_generation_create(context, context->config, context->hosts, context->routes, context->route_bindings, context->route_resolution, MKSYS_LEVEL_CRITICAL, "", &initial_generation)) {
		return false;
	}
	route_generation_registry_publish_status initial_publish_status = listener_generation_publish(context, &initial_generation);
	if (initial_publish_status != ROUTE_GENERATION_REGISTRY_PUBLISH_OK) {
		LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot publish the initial proxy route generation: %s.", listener_generation_publish_error(initial_publish_status));
		route_generation_release(initial_generation);
		listener_generation_active_set(context, NULL);
		return false;
	}
	return true;
}

listener_route_prepare_status listener_generation_prepare(listener_context *context, conf **config, hosts_table **hosts, mksys_level failure_level, const char *failure_action, route_generation **result) {
	if (config == NULL || *config == NULL || hosts == NULL || *hosts == NULL || result == NULL || *result != NULL) {
		return LISTENER_ROUTE_PREPARE_CANDIDATE_ERROR;
	}
	route_bindings *bindings = NULL;
	route_resolution *resolution = NULL;
	route_table *routes = NULL;
	route_table_build_status route_status = route_table_build(*config, &routes);
	if (route_status != ROUTE_TABLE_BUILD_OK) {
		LISTENER_LOG(context, failure_level,
			"Cannot prepare proxy routes: %s%s.",
			route_status == ROUTE_TABLE_BUILD_MEMORY ? "memory allocation failed" : "invalid internal route state", failure_action
		);
		return LISTENER_ROUTE_PREPARE_CANDIDATE_ERROR;
	}
	if (!listener_route_bindings_prepare(context, routes, *hosts, failure_level, failure_action, &bindings)) {
		route_table_destroy(routes);
		return LISTENER_ROUTE_PREPARE_CANDIDATE_ERROR;
	}
	listener_route_prepare_status status = listener_route_resolution_prepare(context, bindings, *hosts, failure_level, failure_action, &resolution);
	if (status == LISTENER_ROUTE_PREPARE_OK && !listener_generation_create(context, *config, *hosts, routes, bindings, resolution, failure_level, failure_action, result)) {
		status = LISTENER_ROUTE_PREPARE_CANDIDATE_ERROR;
	}
	if (status == LISTENER_ROUTE_PREPARE_OK) {
		*config = NULL;
		*hosts = NULL;
		return status;
	}
	route_resolution_destroy(resolution);
	route_bindings_destroy(bindings);
	route_table_destroy(routes);
	return status;
}

route_generation_registry_publish_status listener_generation_publish(listener_context *context, route_generation **candidate) {
	if (context == NULL || candidate == NULL || *candidate == NULL || context->resolver == NULL) {
		errno = EINVAL;
		return ROUTE_GENERATION_REGISTRY_PUBLISH_BAD_ARGUMENT;
	}
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
		return ROUTE_GENERATION_REGISTRY_PUBLISH_TIME;
	}
	route_generation_registry_publish_status status = route_generation_registry_publish(context->generations, candidate, context->resolver, &now);
	if (*candidate == NULL) {
		route_generation *active = route_generation_registry_active(context->generations);
		if (active == NULL) {
			errno = EINVAL;
			return ROUTE_GENERATION_REGISTRY_PUBLISH_BAD_ARGUMENT;
		}
		listener_generation_active_set(context, active);
		context->generation_next_identity = context->generation_next_identity == UINT64_MAX ? 0 : context->generation_next_identity + 1U;
	}
	switch (status) {
		case ROUTE_GENERATION_REGISTRY_PUBLISH_BAD_ARGUMENT:
			errno = EINVAL;
			break;
		case ROUTE_GENERATION_REGISTRY_PUBLISH_IO:
			errno = EIO;
			break;
		case ROUTE_GENERATION_REGISTRY_PUBLISH_TIME:
			errno = EOVERFLOW;
			break;
		case ROUTE_GENERATION_REGISTRY_PUBLISH_BLOCKED:
		case ROUTE_GENERATION_REGISTRY_PUBLISH_OK:
			break;
	}
	return status;
}

const char *listener_generation_publish_error(route_generation_registry_publish_status status) {
	return status == ROUTE_GENERATION_REGISTRY_PUBLISH_BLOCKED ? "a retired generation is still pinned" : strerror(errno);
}

bool listener_hosts_prepare(listener_context *context, mksys_level failure_level, const char *failure_action, hosts_table **result) {
	if (result == NULL || *result != NULL) {
		return false;
	}
	size_t malformed_line_count = 0;
	hosts_load_status status = hosts_table_load(LISTENER_HOSTS_FILENAME, result, &malformed_line_count);
	if (status != HOSTS_LOAD_OK && status != HOSTS_LOAD_FILE_ERROR) {
		LISTENER_LOG(context, failure_level,
			"Cannot prepare local static host table from %s: %s%s.",
			LISTENER_HOSTS_FILENAME, listener_hosts_load_error(status), failure_action
		);
		return false;
	}
	if (*result == NULL) {
		LISTENER_LOG(context, failure_level,
			"Cannot prepare local static host table from %s: loader returned no table%s.",
			LISTENER_HOSTS_FILENAME, failure_action
		);
		return false;
	}
	if (status == HOSTS_LOAD_FILE_ERROR) {
		LISTENER_LOG(context, MKSYS_LEVEL_WARNING,
			"Cannot read local static host table from %s; using guaranteed localhost entries.",
			LISTENER_HOSTS_FILENAME
		);
	}
	if (malformed_line_count > 0) {
		LISTENER_LOG(context, MKSYS_LEVEL_WARNING,
			"Ignored %zu malformed line%s while loading local static host table from %s.",
			malformed_line_count, malformed_line_count == 1 ? "" : "s", LISTENER_HOSTS_FILENAME
		);
	}
	return true;
}
