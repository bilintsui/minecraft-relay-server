/*
 * route/resolution.h: Header file of route/resolution.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_ROUTE_RESOLUTION_H_INCLUDED_

#define _MRS_ROUTE_RESOLUTION_H_INCLUDED_

/* section: headers (library) */
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

/* section: headers (project) */
#include "../resolver/cache.h"
#include "../resolver/hosts.h"
#include "../resolver/supervisor.h"
#include "bindings.h"

/* section: types */
typedef struct route_resolution route_resolution;
typedef enum {
	ROUTE_RESOLUTION_BUILD_OK,
	ROUTE_RESOLUTION_BUILD_BAD_ARGUMENT,
	ROUTE_RESOLUTION_BUILD_MEMORY
} route_resolution_build_status;
typedef enum {
	ROUTE_RESOLUTION_COMPLETION_OK,
	ROUTE_RESOLUTION_COMPLETION_IGNORED,
	ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT,
	ROUTE_RESOLUTION_COMPLETION_IO,
	ROUTE_RESOLUTION_COMPLETION_TIME
} route_resolution_completion_status;
typedef enum {
	ROUTE_RESOLUTION_DESTINATION_PENDING,
	ROUTE_RESOLUTION_DESTINATION_AVAILABLE,
	ROUTE_RESOLUTION_DESTINATION_UNAVAILABLE,
	ROUTE_RESOLUTION_DESTINATION_SERVICE_UNAVAILABLE,
	ROUTE_RESOLUTION_DESTINATION_CONTRADICTORY
} route_resolution_destination_result;
typedef struct {
	bool first_terminal;
	size_t pending_entry_count;
	route_resolution_destination_result result;
	const dns_srv_record *srv_records;
	size_t srv_record_count;
	size_t target_count;
} route_resolution_destination_view;
typedef enum {
	ROUTE_RESOLUTION_TARGET_NUMERIC,
	ROUTE_RESOLUTION_TARGET_HOSTS,
	ROUTE_RESOLUTION_TARGET_DNS
} route_resolution_target_source;
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
	const net_addr *addresses;
	size_t address_count;
	resolver_cache_entry *ipv4_entry;
	resolver_cache_entry *ipv6_entry;
	const char *name;
	net_addr numeric_address;
	route_resolution_target_source source;
} route_resolution_target_view;
typedef enum {
	ROUTE_RESOLUTION_RELEASE_OK,
	ROUTE_RESOLUTION_RELEASE_BAD_ARGUMENT,
	ROUTE_RESOLUTION_RELEASE_IO,
	ROUTE_RESOLUTION_RELEASE_TIME
} route_resolution_release_status;

/* section: functions (exported) */
/* Release every background interest still owned by this live generation. Each local ownership marker is cleared even when supervisor I/O fails. */
route_resolution_release_status route_resolution_background_release(route_resolution *resolution, resolver_supervisor *supervisor, const struct timespec *now);
/* The bindings, hosts table, and cache must outlive the returned generation coordinator. Building observes fresh entries at now so a replacement generation retains discovered targets
 * before the old generation is destroyed. A forked worker may destroy its private copy without affecting listener-owned references.
 */
route_resolution_build_status route_resolution_build(const route_bindings *bindings, const hosts_table *hosts, resolver_cache *cache, const struct timespec *now,
	route_resolution **result);
/* Observing a completion never consumes it; the caller remains responsible for completion destruction. */
route_resolution_completion_status route_resolution_completion_observe(route_resolution *resolution, const resolver_supervisor_completion *completion, const struct timespec *now);
/* Normal listener completion observation also releases obsolete dynamic background interests through this temporary supervisor context. */
route_resolution_completion_status route_resolution_completion_observe_with_supervisor(route_resolution *resolution, resolver_supervisor *supervisor,
	const resolver_supervisor_completion *completion, const struct timespec *now);
void route_resolution_destroy(route_resolution *resolution);
size_t route_resolution_destination_count(const route_resolution *resolution);
/* first_terminal is monotonic for READY gating; result and targets describe the generation's current route-level resolution state. */
bool route_resolution_destination_get(const route_resolution *resolution, size_t destination_index, route_resolution_destination_view *result);
/* Target views and all pointed-to data are borrowed until the coordinator is updated or destroyed. */
bool route_resolution_destination_target_get(const route_resolution *resolution, size_t destination_index, size_t target_index, route_resolution_target_view *result);
/* CAPACITY and MEMORY are recoverable prewarm pressure; BAD_ARGUMENT, IO, and TIME retire the owning listener resolver runtime. */
route_prewarm_status route_resolution_schedule(route_resolution *resolution, resolver_supervisor *supervisor, const struct timespec *now, size_t batch_limit);
bool route_resolution_scheduling_complete(const route_resolution *resolution);
bool route_resolution_warmup_complete(const route_resolution *resolution);

#endif
