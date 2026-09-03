/*
 * route/prewarmer.c: Bounded route DNS prewarm scheduling
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <stdbool.h>
#include <stddef.h>

/* section: headers (project) */
#include "../resolver/cache.h"
#include "bindings.h"

/* section: headers (self) */
#include "prewarmer.h"

/* section: functions (exported) */
bool route_prewarmer_advance(route_prewarmer *prewarmer) {
	if (prewarmer == NULL || prewarmer->bindings == NULL || prewarmer->next_entry_index >= route_bindings_entry_count(prewarmer->bindings)) {
		return false;
	}
	prewarmer->next_entry_index++;
	return true;
}

bool route_prewarmer_complete(const route_prewarmer *prewarmer) {
	return prewarmer != NULL && prewarmer->bindings != NULL && prewarmer->next_entry_index == route_bindings_entry_count(prewarmer->bindings);
}

bool route_prewarmer_entry_get(const route_prewarmer *prewarmer, resolver_cache_entry **result) {
	if (result != NULL) {
		*result = NULL;
	}
	if (prewarmer == NULL || prewarmer->bindings == NULL || result == NULL || prewarmer->next_entry_index >= route_bindings_entry_count(prewarmer->bindings)) {
		return false;
	}
	return route_bindings_entry_get(prewarmer->bindings, prewarmer->next_entry_index, result);
}

void route_prewarmer_reset(route_prewarmer *prewarmer, const route_bindings *bindings) {
	if (prewarmer == NULL) {
		return;
	}
	prewarmer->bindings = bindings;
	prewarmer->next_entry_index = 0;
}
