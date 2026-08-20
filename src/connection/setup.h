/*
 * connection/setup.h: Header file of setup.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_CONNECTION_SETUP_H_INCLUDED_

#define _MRS_CONNECTION_SETUP_H_INCLUDED_

/* section: headers (library) */
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

/* section: headers (project) */
#include "../config.h"
#include "../network.h"
#include "../route/endpoint.h"

/* section: types */
typedef enum {
	CONNSETUP_ROUTE_BYPASS,
	CONNSETUP_ROUTE_READY,
	CONNSETUP_ROUTE_NO_ROUTE,
	CONNSETUP_ROUTE_UNAVAILABLE
} connsetup_route_status;
typedef struct {
	route_endpoint_snapshot endpoint;
	char icon_b64[CONF_ICON_B64MAX + 1U];
	char log_filename[PATH_MAX];
	uint8_t log_level;
	connsetup_route_status route_status;
} connsetup_snapshot;
typedef enum {
	CONNSETUP_OK,
	CONNSETUP_EABORT,
	CONNSETUP_EUNIDENT,
	CONNSETUP_ENOVHOST,
	CONNSETUP_ENORECORD,
	CONNSETUP_ENOCONNECT,
	CONNSETUP_EOLDCLIENT
} connsetup_status;

/* section: functions (exported) */
/* The snapshot is a self-contained value with no config, route, cache, resolution, or DNS-record pointers. */
connsetup_status connsetup_prepared(int socket_in, int *socket_out, const connsetup_snapshot *snapshot, net_addrbundle addrinfo_in, const uint8_t *inbound, size_t inbound_size);

#endif
