/*
 * listener/short.h: Listener-owned STATUS relay and buffered responses
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_LISTENER_SHORT_H_INCLUDED_

#define _MRS_LISTENER_SHORT_H_INCLUDED_

/* section: headers (library) */
#include <stdint.h>
#include <time.h>

/* section: headers (project) */
#include "../resolver/supervisor.h"
#include "connection.h"
#include "events.h"
#include "metrics.h"

/* section: functions (exported) */
listener_connection_progress listener_short_connect_failure(listener_connection *connection, const listener_events *events, const struct timespec *now);
listener_connection_progress listener_short_event(listener_connection *connection, listener_event_kind kind, uint32_t event_flags,
	uint64_t source_generation, const listener_events *events, const struct timespec *now);
listener_connection_progress listener_short_refuse(listener_connection *connection, const listener_events *events, listener_metrics_state *metrics, resolver_supervisor *supervisor, const struct timespec *now);
listener_connection_progress listener_short_start(listener_connection *connection, const listener_events *events, const char *working_directory, listener_metrics_state *metrics,
	resolver_supervisor *supervisor, const struct timespec *now);

#endif
