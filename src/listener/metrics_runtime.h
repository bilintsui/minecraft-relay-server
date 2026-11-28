/*
 * listener/metrics_runtime.h: Metrics collection and timer coordination for the listener
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_LISTENER_METRICS_RUNTIME_H_INCLUDED_

#define _MRS_LISTENER_METRICS_RUNTIME_H_INCLUDED_

/* section: headers (library) */
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/* section: headers (project) */
#include "events.h"
#include "metrics.h"

/* section: types */
struct listener_context;

/* section: functions (exported) */
void listener_metrics_observations_drain(struct listener_context *context, const struct timespec *now);
void listener_metrics_snapshot_output(struct listener_context *context, listener_metrics_output_reason reason, const char *log_filename, uint8_t log_level, const struct timespec *now);
listener_metrics_timer_read_status listener_metrics_timer_read(struct listener_context *context, listener_events *events, bool event_failed, uint64_t *expirations);
void listener_metrics_timer_set(struct listener_context *context, listener_events *events, uint32_t interval, const char *log_filename, uint8_t log_level);

#endif
