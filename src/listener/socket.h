/*
 * listener/socket.h: Listening endpoints and socket replacement
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_LISTENER_SOCKET_H_INCLUDED_

#define _MRS_LISTENER_SOCKET_H_INCLUDED_

/* section: headers (library) */
#include <netinet/in.h>
#include <stdbool.h>

/* section: headers (project) */
#include "../config.h"
#include "../network.h"
#include "events.h"

/* section: types */
typedef struct {
	net_addr address;
	in_port_t port;
} listener_endpoint;
typedef enum {
	LISTENER_ENDPOINT_OK,
	LISTENER_ENDPOINT_BAD_ADDRESS,
	LISTENER_ENDPOINT_BAD_PORT
} listener_endpoint_status;
typedef struct {
	listener_endpoint endpoint;
	int fd;
} listener_socket;
typedef enum {
	LISTENER_SOCKET_REPLACE_OK,
	LISTENER_SOCKET_REPLACE_CANDIDATE_ERROR,
	LISTENER_SOCKET_REPLACE_ACTIVE_ERROR,
	LISTENER_SOCKET_REPLACE_ROLLBACK_ERROR
} listener_socket_replace_status;

/* section: functions (exported) */
bool listener_endpoint_equal(const listener_endpoint *left, const listener_endpoint *right);
listener_endpoint_status listener_endpoint_prepare(const conf *source, listener_endpoint *target);
int listener_socket_bind(listener_socket *target);
void listener_socket_close(listener_socket *target);
listener_socket_replace_status listener_socket_replace(listener_socket *target, const listener_endpoint *endpoint, const listener_events *events);

#endif
