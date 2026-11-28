/*
 * listener/connection_route.h: Route selection and resolution for a listener-owned connection
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_LISTENER_CONNECTION_ROUTE_H_INCLUDED_

#define _MRS_LISTENER_CONNECTION_ROUTE_H_INCLUDED_

/* section: headers (library) */
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/* section: headers (project) */
#include "../resolver/supervisor.h"
#include "connection.h"
#include "events.h"
#include "metrics.h"

/* section: functions (exported) */
bool listener_connection_route_cancelled(const listener_connection *connection, listener_event_kind kind, uint32_t event_flags);
listener_connection_progress listener_connection_route_progress(listener_connection *connection, listener_metrics_state *metrics, resolver_supervisor *supervisor, const struct timespec *now);
listener_connection_progress listener_connection_route_start(listener_connection *connection, const listener_events *events, listener_metrics_state *metrics,
	resolver_supervisor *supervisor, const struct timespec *now);

#endif
