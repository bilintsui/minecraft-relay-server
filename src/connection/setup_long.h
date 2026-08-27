/*
 * connection/setup_long.h: Header file of connection/setup_long.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_CONNECTION_SETUP_LONG_H_INCLUDED_

#define _MRS_CONNECTION_SETUP_LONG_H_INCLUDED_

/* section: headers (library) */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* section: headers (project) */
#include "../network.h"
#include "../protocol/proxy.h"
#include "../route/endpoint.h"
#include "setup.h"

/* section: defines */
/* The seed carries the optional PROXY header and the complete initial request toward the upstream server. */
#define CONNECTION_SETUP_LONG_PENDING_MAX	(PROTOPROXY_PACKETMAXLEN + BUFSIZ + ROUTE_ENDPOINT_TEXT_SIZE + 32U)

#if CONNECTION_SETUP_LONG_PENDING_MAX > NET_RELAY_BUFFER_BYTES
#error "The long-worker seed must fit in the relay buffer."
#endif

/* section: functions (exported) */
/* The snapshot is a self-contained value with no config, route, cache, resolution, or DNS-record pointers.
 * On success, the caller owns socket_in and *socket_out; on failure, this function closes socket_in and any opened outbound socket. */
connection_setup_status connection_setup_long_prepared(int socket_in, int *socket_out, const connection_setup_snapshot *snapshot, net_addrbundle addrinfo_in,
	const uint8_t *inbound, size_t inbound_size, uint8_t *seed, size_t *seed_size);

#endif
