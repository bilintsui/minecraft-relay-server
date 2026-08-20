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
#include "network.h"
#include "protocol/proxy.h"
#include "route_generation.h"

/* section: defines */
/* snapshot text */
#define ROUTE_ENDPOINT_TEXT_SIZE	(ADDRESS_MAXLEN + 1U)

/* section: types */
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
/* Selection re-views every DNS cache level at now. The returned snapshot owns all of its data and contains no generation or cache pointers. */
route_endpoint_select_status route_endpoint_select(route_generation *generation, const char *vhost, const struct timespec *now, const p_proxy *inbound_proxy,
	route_endpoint_snapshot *result);

#endif
