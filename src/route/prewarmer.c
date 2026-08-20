/*
 * route/prewarmer.c: Bounded route DNS prewarm scheduling
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <time.h>

/* section: headers (project) */
#include "../resolver/cache.h"
#include "../resolver/supervisor.h"
#include "bindings.h"

/* section: headers (self) */
#include "prewarmer.h"

/* section: functions (local) */
static route_prewarm_status route_prewarmer_schedule_status(resolver_supervisor_schedule_status status) {
	switch (status) {
		case RESOLVER_SUPERVISOR_SCHEDULE_STARTED:
		case RESOLVER_SUPERVISOR_SCHEDULE_COALESCED:
		case RESOLVER_SUPERVISOR_SCHEDULE_COMPLETE:
		case RESOLVER_SUPERVISOR_SCHEDULE_FRESH:
			return ROUTE_PREWARM_MORE;
		case RESOLVER_SUPERVISOR_SCHEDULE_LIMIT:
			return ROUTE_PREWARM_CAPACITY;
		case RESOLVER_SUPERVISOR_SCHEDULE_IO:
			return ROUTE_PREWARM_IO;
		case RESOLVER_SUPERVISOR_SCHEDULE_MEMORY:
			return ROUTE_PREWARM_MEMORY;
		case RESOLVER_SUPERVISOR_SCHEDULE_TIME:
			return ROUTE_PREWARM_TIME;
		case RESOLVER_SUPERVISOR_SCHEDULE_BAD_ARGUMENT:
		default:
			return ROUTE_PREWARM_BAD_ARGUMENT;
	}
}

/* section: functions (exported) */
bool route_prewarmer_complete(const route_prewarmer *prewarmer) {
	return prewarmer != NULL && prewarmer->bindings != NULL && prewarmer->next_entry_index == route_bindings_entry_count(prewarmer->bindings);
}

void route_prewarmer_reset(route_prewarmer *prewarmer, const route_bindings *bindings) {
	if (prewarmer == NULL) {
		return;
	}
	prewarmer->bindings = bindings;
	prewarmer->next_entry_index = 0;
}

route_prewarm_status route_prewarmer_schedule(route_prewarmer *prewarmer, resolver_supervisor *supervisor, const struct timespec *now, size_t batch_limit) {
	if (prewarmer == NULL || prewarmer->bindings == NULL || supervisor == NULL || now == NULL || batch_limit == 0
		|| prewarmer->next_entry_index > route_bindings_entry_count(prewarmer->bindings)) {
		return ROUTE_PREWARM_BAD_ARGUMENT;
	}
	for (size_t attempt = 0; attempt < batch_limit && !route_prewarmer_complete(prewarmer); attempt++) {
		route_prewarm_step step = { 0 };
		route_prewarm_status status = route_prewarmer_step(prewarmer, supervisor, now, &step);
		if (status != ROUTE_PREWARM_MORE && status != ROUTE_PREWARM_COMPLETE) {
			return status;
		}
	}
	return route_prewarmer_complete(prewarmer) ? ROUTE_PREWARM_COMPLETE : ROUTE_PREWARM_MORE;
}

route_prewarm_status route_prewarmer_step(route_prewarmer *prewarmer, resolver_supervisor *supervisor, const struct timespec *now, route_prewarm_step *result) {
	if (result != NULL) {
		memset(result, 0, sizeof(*result));
	}
	if (prewarmer == NULL || prewarmer->bindings == NULL || supervisor == NULL || now == NULL || result == NULL
		|| prewarmer->next_entry_index > route_bindings_entry_count(prewarmer->bindings)) {
		return ROUTE_PREWARM_BAD_ARGUMENT;
	}
	if (route_prewarmer_complete(prewarmer)) {
		return ROUTE_PREWARM_COMPLETE;
	}
	if (!route_bindings_entry_get(prewarmer->bindings, prewarmer->next_entry_index, &result->entry)) {
		return ROUTE_PREWARM_BAD_ARGUMENT;
	}
	result->schedule_status = resolver_supervisor_entry_schedule(supervisor, result->entry, now);
	route_prewarm_status status = route_prewarmer_schedule_status(result->schedule_status);
	if (status == ROUTE_PREWARM_MORE) {
		prewarmer->next_entry_index++;
		return route_prewarmer_complete(prewarmer) ? ROUTE_PREWARM_COMPLETE : ROUTE_PREWARM_MORE;
	}
	return status;
}
