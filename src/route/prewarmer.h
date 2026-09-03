/*
 * route/prewarmer.h: Header file of route/prewarmer.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_ROUTE_PREWARMER_H_INCLUDED_

#define _MRS_ROUTE_PREWARMER_H_INCLUDED_

/* section: headers (library) */
#include <stdbool.h>
#include <stddef.h>

/* section: headers (project) */
#include "../resolver/cache.h"
#include "bindings.h"

/* section: types */
typedef struct {
	const route_bindings *bindings;
	size_t next_entry_index;
} route_prewarmer;

/* section: functions (exported) */
bool route_prewarmer_advance(route_prewarmer *prewarmer);
bool route_prewarmer_complete(const route_prewarmer *prewarmer);
bool route_prewarmer_entry_get(const route_prewarmer *prewarmer, resolver_cache_entry **result);
/* The borrowed bindings generation must outlive the prewarmer or be replaced through reset before destruction. */
void route_prewarmer_reset(route_prewarmer *prewarmer, const route_bindings *bindings);

#endif
