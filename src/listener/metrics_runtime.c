/*
 * listener/metrics_runtime.c: Metrics collection and timer coordination for the listener
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/* section: headers (project) */
#include "../log.h"
#include "../resolver/cache.h"
#include "../resolver/supervisor.h"
#include "../timeutil.h"
#include "context.h"
#include "events.h"
#include "metrics.h"

/* section: headers (self) */
#include "metrics_runtime.h"

/* section: functions (local) */
static bool listener_metrics_aggregate_snapshot_get(const listener_context *context, listener_metrics_aggregate_snapshot *snapshot) {
	return context != NULL && snapshot != NULL && listener_metrics_snapshot_get(&context->metrics, &snapshot->listener)
		&& resolver_cache_metrics_get(context->dns_cache, &snapshot->cache)
		&& resolver_supervisor_metrics_assembly_get(context->resolver, &snapshot->assembly)
		&& resolver_supervisor_metrics_get(context->resolver, &snapshot->supervisor);
}

static void listener_metrics_timer_failure(listener_context *context, int failure_errno, const char *log_filename, uint8_t log_level) {
	listener_metrics_scheduler_failure_record(&context->metrics_runtime);
	MKSYS_LOG(log_filename, log_level, MKSYS_LEVEL_WARNING, "Metrics timer disabled after an observation-subsystem failure: %s", strerror(failure_errno));
}

/* section: functions (exported) */
void listener_metrics_observations_drain(listener_context *context, const struct timespec *now) {
	if (context == NULL || context->resolver == NULL || !timeutil_valid(now)) {
		return;
	}
	resolver_supervisor_observation observation;
	while (resolver_supervisor_observation_take(context->resolver, &observation)) {
		listener_metrics_helper_observation_log(&context->metrics_runtime, &observation, context->log_filename, context->config->log.level, now);
	}
	listener_metrics_helper_observation_loss_log(&context->metrics_runtime, resolver_supervisor_observation_dropped(context->resolver), context->log_filename, context->config->log.level, now);
}

void listener_metrics_snapshot_output(listener_context *context, listener_metrics_output_reason reason, const char *log_filename, uint8_t log_level, const struct timespec *now) {
	int saved_errno = errno;
	listener_metrics_aggregate_snapshot snapshot;
	if (listener_metrics_aggregate_snapshot_get(context, &snapshot)) {
		listener_metrics_output(&context->metrics_runtime, reason, &snapshot, log_filename, log_level, now);
	} else {
		listener_metrics_format_drop_record(&context->metrics_runtime);
	}
	errno = saved_errno;
}

listener_metrics_timer_read_status listener_metrics_timer_read(listener_context *context, listener_events *events, bool event_failed, uint64_t *expirations) {
	int saved_errno = errno;
	listener_metrics_timer_read_status status = listener_events_metrics_timer_read(events, event_failed, expirations);
	if (status == LISTENER_METRICS_TIMER_FAILED) {
		listener_metrics_timer_failure(context, errno, context->log_filename, context->config->log.level);
	}
	errno = saved_errno;
	return status;
}

void listener_metrics_timer_set(listener_context *context, listener_events *events, uint32_t interval, const char *log_filename, uint8_t log_level) {
	int saved_errno = errno;
	if (listener_events_metrics_timer_set(events, interval) == -1) {
		listener_metrics_timer_failure(context, errno, log_filename, log_level);
	}
	errno = saved_errno;
}
