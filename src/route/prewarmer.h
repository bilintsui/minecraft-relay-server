/*
 * route/prewarmer.h: Bounded route DNS prewarm scheduling
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_ROUTE_PREWARMER_H_INCLUDED_

#define _MRS_ROUTE_PREWARMER_H_INCLUDED_

/* section: headers (library) */
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

/* section: headers (project) */
#include "../resolver/supervisor.h"
#include "bindings.h"

/* section: types */
typedef struct {
	const route_bindings *bindings;
	size_t next_entry_index;
} route_prewarmer;
typedef enum {
	ROUTE_PREWARM_COMPLETE,
	ROUTE_PREWARM_MORE,
	ROUTE_PREWARM_CAPACITY,
	ROUTE_PREWARM_BAD_ARGUMENT,
	ROUTE_PREWARM_IO,
	ROUTE_PREWARM_MEMORY,
	ROUTE_PREWARM_TIME
} route_prewarm_status;
typedef struct {
	resolver_cache_entry *entry;
	resolver_supervisor_schedule_status schedule_status;
} route_prewarm_step;

/* section: functions (exported) */
bool route_prewarmer_complete(const route_prewarmer *prewarmer);
/* The borrowed bindings generation must outlive the prewarmer or be replaced through reset before destruction. */
void route_prewarmer_reset(route_prewarmer *prewarmer, const route_bindings *bindings);
/* batch_limit bounds schedule calls made by one listener event-loop turn. */
route_prewarm_status route_prewarmer_schedule(route_prewarmer *prewarmer, resolver_supervisor *supervisor, const struct timespec *now, size_t batch_limit);
/* A successful step reports the exact supervisor result so completion-aware coordinators can distinguish FRESH from COMPLETE without consuming either twice. */
route_prewarm_status route_prewarmer_step(route_prewarmer *prewarmer, resolver_supervisor *supervisor, const struct timespec *now, route_prewarm_step *result);

#endif
