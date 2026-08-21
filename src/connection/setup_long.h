/*
 * connection/setup_long.h: Header file of setup_long.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_CONNECTION_SETUP_LONG_H_INCLUDED_

#define _MRS_CONNECTION_SETUP_LONG_H_INCLUDED_

/* section: headers (library) */
#include <stddef.h>
#include <stdint.h>

/* section: headers (project) */
#include "setup.h"

/* section: functions (exported) */
/* The snapshot is a self-contained value with no config, route, cache, resolution, or DNS-record pointers. */
connection_setup_status connection_setup_long_prepared(int socket_in, int *socket_out, const connection_setup_snapshot *snapshot, net_addrbundle addrinfo_in,
	const uint8_t *inbound, size_t inbound_size);

#endif
