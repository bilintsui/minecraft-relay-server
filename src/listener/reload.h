/*
 * listener/reload.h: Configuration and local hosts reloads
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_LISTENER_RELOAD_H_INCLUDED_

#define _MRS_LISTENER_RELOAD_H_INCLUDED_

/* section: headers (library) */
#include <stdbool.h>

/* section: headers (project) */
#include "events.h"
#include "socket.h"

/* section: types */
struct listener_context;

/* section: functions (exported) */
int listener_hosts_reload(struct listener_context *context);
bool listener_hosts_watch_process(struct listener_context *context, listener_events *events, bool failed, bool ready);
void listener_hosts_watch_retry(struct listener_context *context, listener_events *events);
int listener_reload(struct listener_context *context, listener_socket *listener, listener_events *events, bool *metrics_readiness_invalidated);

#endif
