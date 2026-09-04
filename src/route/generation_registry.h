/*
 * route/generation_registry.h: Header file of route/generation_registry.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_ROUTE_GENERATION_REGISTRY_H_INCLUDED_

#define _MRS_ROUTE_GENERATION_REGISTRY_H_INCLUDED_

/* section: headers (library) */
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

/* section: headers (project) */
#include "../resolver/supervisor.h"
#include "generation.h"
#include "resolution.h"

/* section: types */
typedef struct route_generation_registry route_generation_registry;
typedef enum {
	ROUTE_GENERATION_REGISTRY_COLLECT_NONE,
	ROUTE_GENERATION_REGISTRY_COLLECT_RETAINED,
	ROUTE_GENERATION_REGISTRY_COLLECT_COLLECTED,
	ROUTE_GENERATION_REGISTRY_COLLECT_BAD_ARGUMENT,
	ROUTE_GENERATION_REGISTRY_COLLECT_IO,
	ROUTE_GENERATION_REGISTRY_COLLECT_TIME
} route_generation_registry_collect_status;
typedef enum {
	ROUTE_GENERATION_REGISTRY_PUBLISH_OK,
	ROUTE_GENERATION_REGISTRY_PUBLISH_BLOCKED,
	ROUTE_GENERATION_REGISTRY_PUBLISH_BAD_ARGUMENT,
	ROUTE_GENERATION_REGISTRY_PUBLISH_IO,
	ROUTE_GENERATION_REGISTRY_PUBLISH_TIME
} route_generation_registry_publish_status;

/* section: functions (exported) */
route_generation *route_generation_registry_active(const route_generation_registry *registry);
/* The caller owns the returned reference and must release it before a worker fork or connection failure. */
route_generation *route_generation_registry_active_retain(route_generation_registry *registry);
/* Releases a retired generation when only the registry reference remains. */
route_generation_registry_collect_status route_generation_registry_collect(route_generation_registry *registry, resolver_supervisor *supervisor, const struct timespec *now);
/* Every completion is offered to both live coordinators before the aggregate status is returned. */
route_resolution_completion_status route_generation_registry_completion_observe(route_generation_registry *registry, const resolver_supervisor_completion *completion,
	resolver_supervisor *supervisor, const struct timespec *now);
route_generation_registry *route_generation_registry_create(void);
void route_generation_registry_destroy(route_generation_registry *registry);
/* Use only in a forked non-listener child. This destroys both private COW generation copies regardless of inherited reference counts. */
void route_generation_registry_dispose_in_child(route_generation_registry *registry);
/* Candidate ownership transfers at the active/retired swap, including a post-commit fatal status. Publication is blocked while a pinned retired generation remains live. */
route_generation_registry_publish_status route_generation_registry_publish(route_generation_registry *registry, route_generation **candidate, resolver_supervisor *supervisor,
	const struct timespec *now);
route_generation *route_generation_registry_retired(const route_generation_registry *registry);

#endif
