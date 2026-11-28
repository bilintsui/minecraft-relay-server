/*
 * listener/workers.h: Listener worker admission, fork handoff and reaping
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_LISTENER_WORKERS_H_INCLUDED_

#define _MRS_LISTENER_WORKERS_H_INCLUDED_

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
listener_connection_progress listener_workers_dispatch(listener_connection *connections, listener_connection *connection, listener_socket *listener, listener_events *events,
	pid_t listener_pid, struct listener_context *context, const struct timespec *now);
int listener_workers_reap(struct listener_context *context);

#endif
