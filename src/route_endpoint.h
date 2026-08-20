/*
 * route_endpoint.h: Fresh route endpoint selection and worker snapshots
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_ROUTE_ENDPOINT_H_INCLUDED_

#define _MRS_ROUTE_ENDPOINT_H_INCLUDED_

/* section: headers (library) */
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* section: headers (project) */
#include "define/global.h"
#include "dns.h"
#include "network.h"
#include "protocol/proxy.h"
#include "resolver_cache.h"
#include "route_generation.h"

/* section: defines */
/* snapshot text */
#define ROUTE_ENDPOINT_TEXT_SIZE	(ADDRESS_MAXLEN + 1U)

/* one SRV owner plus the selected target's address families */
#define ROUTE_ENDPOINT_REQUIREMENT_LIMIT	3

/* section: types */
typedef enum {
	ROUTE_ENDPOINT_OVERLAY_NONE,
	ROUTE_ENDPOINT_OVERLAY_POSITIVE,
	ROUTE_ENDPOINT_OVERLAY_UNAVAILABLE
} route_endpoint_overlay_status;
typedef struct route_endpoint_overlay {
	const dns_address_record *addresses;
	size_t address_count;
	resolver_cache_entry *entry;
	const struct route_endpoint_overlay *next;
	const dns_srv_record *srv_records;
	size_t srv_record_count;
	route_endpoint_overlay_status status;
} route_endpoint_overlay;
typedef struct {
	resolver_cache_entry *entry;
	bool pending;
} route_endpoint_requirement;
typedef struct {
	size_t count;
	route_endpoint_requirement items[ROUTE_ENDPOINT_REQUIREMENT_LIMIT];
} route_endpoint_requirements;
typedef enum {
	ROUTE_ENDPOINT_SELECT_OK,
	ROUTE_ENDPOINT_SELECT_BAD_ARGUMENT,
	ROUTE_ENDPOINT_SELECT_CONTRADICTORY,
	ROUTE_ENDPOINT_SELECT_LIMIT,
	ROUTE_ENDPOINT_SELECT_NO_ROUTE,
	ROUTE_ENDPOINT_SELECT_PENDING,
	ROUTE_ENDPOINT_SELECT_SERVICE_UNAVAILABLE,
	ROUTE_ENDPOINT_SELECT_UNAVAILABLE
} route_endpoint_select_status;
typedef struct {
	net_addr address;
	char configured_address[ROUTE_ENDPOINT_TEXT_SIZE];
	size_t destination_index;
	uint64_t generation_identity;
	p_proxy inbound_proxy;
	in_port_t port;
	bool pheader;
	bool rewrite;
	char target_name[ROUTE_ENDPOINT_TEXT_SIZE];
	char vhost[ROUTE_ENDPOINT_TEXT_SIZE];
} route_endpoint_snapshot;

/* section: functions (exported) */
/* Evaluation reports the cache-entry chain that determined a pending result. Overlays are event-scoped waiter-owned results and never modify the shared cache. */
route_endpoint_select_status route_endpoint_evaluate(route_generation *generation, const char *vhost, const struct timespec *now, const p_proxy *inbound_proxy,
	const route_endpoint_overlay *overlays, route_endpoint_requirements *requirements, route_endpoint_snapshot *result);
/* Selection re-views every DNS cache level at now. The returned snapshot owns all of its data and contains no generation or cache pointers. */
route_endpoint_select_status route_endpoint_select(route_generation *generation, const char *vhost, const struct timespec *now, const p_proxy *inbound_proxy,
	route_endpoint_snapshot *result);

#endif
