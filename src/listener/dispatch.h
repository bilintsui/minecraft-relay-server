/*
 * listener/dispatch.h: Dispatch listener connection events and route waiters
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_LISTENER_DISPATCH_H_INCLUDED_

#define _MRS_LISTENER_DISPATCH_H_INCLUDED_

/* section: headers (library) */
#include <sys/types.h>
#include <time.h>

/* section: headers (project) */
#include "connection.h"
#include "events.h"
#include "socket.h"

/* section: types */
struct listener_context;

/* section: functions (exported) */
/* Refreshes now before processing timeouts, for use through the end of the event batch. */
int listener_dispatch_batch(const listener_requests *requests, listener_connection *connections, listener_socket *listener, listener_events *events, pid_t listener_pid,
	struct listener_context *context, struct timespec *now);
void listener_dispatch_mark_cancelled(const listener_requests *requests);
int listener_dispatch_route_waiters(listener_connection *connections, listener_socket *listener, listener_events *events, pid_t listener_pid, struct listener_context *context, const struct timespec *now);

#endif
