/*
 * connection/setup.h: Shared connection setup types and helpers
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_CONNECTION_SETUP_H_INCLUDED_

#define _MRS_CONNECTION_SETUP_H_INCLUDED_

/* section: headers (library) */
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* section: headers (project) */
#include "../config.h"
#include "../network.h"
#include "../route/endpoint.h"

/* section: types */
typedef enum {
	CONNECTION_SETUP_ROUTE_BYPASS,
	CONNECTION_SETUP_ROUTE_READY,
	CONNECTION_SETUP_ROUTE_NO_ROUTE,
	CONNECTION_SETUP_ROUTE_UNAVAILABLE
} connection_setup_route_status;
typedef struct {
	route_endpoint_snapshot endpoint;
	char icon_b64[CONF_ICON_B64MAX + 1U];
	char log_filename[PATH_MAX];
	uint8_t log_level;
	connection_setup_route_status route_status;
} connection_setup_snapshot;
typedef enum {
	CONNECTION_SETUP_OK,
	CONNECTION_SETUP_EABORT,
	CONNECTION_SETUP_EUNIDENT,
	CONNECTION_SETUP_ENOVHOST,
	CONNECTION_SETUP_ENORECORD,
	CONNECTION_SETUP_ENOCONNECT,
	CONNECTION_SETUP_EOLDCLIENT
} connection_setup_status;

/* section: functions (exported) */
/* The snapshot is a self-contained value with no config, route, cache, resolution, or DNS-record pointers. */
bool connection_setup_address_valid(const net_addr *address);
bool connection_setup_bundle_valid(const net_addrbundle *address);
const char *connection_setup_destination(const route_endpoint_snapshot *endpoint);
bool connection_setup_snapshot_valid(const connection_setup_snapshot *snapshot);

#endif
