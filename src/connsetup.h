/*
 * connsetup.h: Header file of connsetup.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_CONNSETUP_H_INCLUDED_

#define _MRS_CONNSETUP_H_INCLUDED_

/* section: headers (library) */
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

/* section: headers (project) */
#include "config.h"
#include "network.h"
#include "route_endpoint.h"

/* section: defines */
/* error code */
#define CONNSETUP_OK	0
#define CONNSETUP_EABORT	1
#define CONNSETUP_EUNIDENT	2
#define CONNSETUP_ENOVHOST	3
#define CONNSETUP_ENORECORD	4
#define CONNSETUP_ENOCONNECT	5
#define CONNSETUP_EOLDCLIENT	6

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

/* section: functions (exported) */
/* The snapshot is a self-contained value with no config, route, cache, resolution, or DNS-record pointers. */
int connsetup_prepared(int socket_in, int *socket_out, const connsetup_snapshot *snapshot, net_addrbundle addrinfo_in, const uint8_t *inbound, size_t inbound_size);

#endif
