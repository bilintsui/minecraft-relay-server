/*
 * listener_metrics.c: Listener-owned capacity and route metrics
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

/* section: headers (project) */
#include "config.h"
#include "log.h"
#include "metrics.h"
#include "resolver/cache.h"
#include "resolver/ipc_assembly.h"
#include "resolver/supervisor.h"
#include "timeutil.h"

/* section: headers (self) */
#include "listener_metrics.h"

/* section: defines */
#define LISTENER_METRICS_HELPER_LOG_INTERVAL_SEC	10U

/* section: types */
typedef struct {
	char *data;
	bool failed;
	size_t length;
	size_t size;
} listener_metrics_line_builder;

/* section: global variables */
static const char *const listener_metrics_failure_names[] = { "none", "exit", "io", "protocol", "spawn", "timeout" };
static const char *const listener_metrics_output_reason_names[] = { "startup", "periodic", "reconfigure", "disable", "shutdown" };
static const char *const listener_metrics_payload_kind_names[] = { "positive", "nxdomain", "nodata" };
static const char *const listener_metrics_priority_names[] = { "background", "interactive" };
static const char *const listener_metrics_query_type_names[] = { "a", "aaaa", "srv", "other" };
static const char *const listener_metrics_recovery_names[] = { "success_streak", "stable_uptime" };
static const char *const listener_metrics_request_mode_names[] = { "short", "worker" };

/* section: functions (local) */
static void listener_metrics_counter_add(uint64_t *counter, uint64_t amount) {
	*counter = UINT64_MAX - *counter < amount ? UINT64_MAX : *counter + amount;
}

static void listener_metrics_decrement(listener_metrics_state *metrics, uint64_t *gauge) {
	if (*gauge > 0) {
		(*gauge)--;
	} else {
		(void)metrics_counter_add(&metrics->saturation_total, 1, &metrics->saturation_total);
	}
}

static bool listener_metrics_duration_milliseconds(const struct timespec *start, const struct timespec *end, uint64_t *result) {
	if (!timeutil_valid(start) || !timeutil_valid(end) || result == NULL || timeutil_compare(end, start) < 0) {
		return false;
	}
	uintmax_t seconds = (uintmax_t)end->tv_sec - (uintmax_t)start->tv_sec;
	uintmax_t nanoseconds;
	if (end->tv_nsec < start->tv_nsec) {
		seconds--;
		nanoseconds = UINTMAX_C(1000000000) + (uintmax_t)end->tv_nsec - (uintmax_t)start->tv_nsec;
	} else {
		nanoseconds = (uintmax_t)end->tv_nsec - (uintmax_t)start->tv_nsec;
	}
	if (seconds > (UINT64_MAX - nanoseconds / UINTMAX_C(1000000)) / UINT64_C(1000)) {
		return false;
	}
	*result = (uint64_t)(seconds * UINTMAX_C(1000) + nanoseconds / UINTMAX_C(1000000));
	return true;
}

static void listener_metrics_helper_line_emit(listener_metrics_runtime *runtime, const char *log_filename, uint8_t log_level, mksys_level message_level, const char *helper_line) {
	if (mksysmsg(MKSYS_PREFIX_ON, log_filename, log_level, message_level, MKSYS_LINE_END, "%s", helper_line) != 0) {
		listener_metrics_counter_add(&runtime->logger_errors, 1);
	}
}

static void listener_metrics_increment(listener_metrics_state *metrics, uint64_t *counter) {
	(void)metrics_counter_add(counter, 1, &metrics->saturation_total);
}

static bool listener_metrics_line_append(listener_metrics_line_builder *builder, const char *format, ...) {
	if (builder->failed) {
		return false;
	}
	va_list arguments;
	va_start(arguments, format);
	int length = vsnprintf(builder->data + builder->length, builder->size - builder->length, format, arguments);
	va_end(arguments);
	if (length < 0 || (size_t)length >= builder->size - builder->length) {
		builder->failed = true;
		return false;
	}
	builder->length += (size_t)length;
	return true;
}

static void listener_metrics_line_begin(listener_metrics_line_builder *builder, char *line, size_t line_size, const listener_metrics_runtime *runtime, uint64_t sequence, const char *family) {
	memset(builder, 0, sizeof(*builder));
	builder->data = line;
	builder->size = line_size;
	(void)listener_metrics_line_append(builder, "metrics schema=1 seq=%" PRIu64 " family=%s instance=%jd-%jd-%ld", sequence, family,
		(intmax_t)runtime->process_id, (intmax_t)runtime->started_at.tv_sec, runtime->started_at.tv_nsec);
}

static void listener_metrics_line_emit(listener_metrics_runtime *runtime, const char *log_filename, uint8_t log_level, listener_metrics_line_builder *builder, const char *metrics_line) {
	if (builder->failed || builder->length == 0 || builder->length >= LISTENER_METRICS_LINE_SIZE) {
		listener_metrics_counter_add(&runtime->format_drops, 1);
		return;
	}
	if (mksysmsg(MKSYS_PREFIX_ON, log_filename, log_level, MKSYS_LEVEL_INFORMATION, MKSYS_LINE_END, "%s", metrics_line) != 0) {
		listener_metrics_counter_add(&runtime->logger_errors, 1);
	}
}

static bool listener_metrics_rate_limit_ready(bool valid, const struct timespec *last, const struct timespec *now) {
	if (!valid) {
		return true;
	}
	struct timespec eligible_at;
	return timeutil_add_seconds(last, LISTENER_METRICS_HELPER_LOG_INTERVAL_SEC, &eligible_at) && timeutil_compare(now, &eligible_at) >= 0;
}

/* section: functions (exported) */
void listener_metrics_accept_capacity_rejected_record(listener_metrics_state *metrics) {
	if (metrics != NULL) {
		listener_metrics_increment(metrics, &metrics->accept_capacity_rejected);
	}
}

void listener_metrics_accept_fd_exhausted_record(listener_metrics_state *metrics) {
	if (metrics != NULL) {
		listener_metrics_increment(metrics, &metrics->accept_fd_exhausted);
	}
}

void listener_metrics_accept_record(listener_metrics_state *metrics) {
	if (metrics != NULL) {
		listener_metrics_increment(metrics, &metrics->accepted);
	}
}

void listener_metrics_connection_add(listener_metrics_state *metrics) {
	if (metrics == NULL) {
		return;
	}
	listener_metrics_increment(metrics, &metrics->connections_current);
	metrics_high_water_update(&metrics->connections_high_water, metrics->connections_current);
}

void listener_metrics_connection_remove(listener_metrics_state *metrics) {
	if (metrics != NULL) {
		listener_metrics_decrement(metrics, &metrics->connections_current);
	}
}

void listener_metrics_connection_track_failure_record(listener_metrics_state *metrics) {
	if (metrics != NULL) {
		listener_metrics_increment(metrics, &metrics->connection_track_failure);
	}
}

bool listener_metrics_effectively_enabled(const conf *config) {
	return config != NULL && config->metrics.interval > 0 && config->log.level >= MKSYS_LEVEL_INFORMATION;
}

void listener_metrics_format_drop_record(listener_metrics_runtime *runtime) {
	if (runtime != NULL) {
		listener_metrics_counter_add(&runtime->format_drops, 1);
	}
}

void listener_metrics_helper_observation_log(listener_metrics_runtime *runtime, const resolver_supervisor_observation *observation, const char *log_filename, uint8_t log_level,
	const struct timespec *processed_at) {
	int saved_errno = errno;
	if (runtime == NULL || observation == NULL || log_filename == NULL || !timeutil_valid(processed_at)) {
		errno = saved_errno;
		return;
	}
	if (observation->type != RESOLVER_SUPERVISOR_OBSERVATION_DEGRADED && observation->type != RESOLVER_SUPERVISOR_OBSERVATION_RECOVERED) {
		errno = saved_errno;
		return;
	}
	size_t slot = observation->type == RESOLVER_SUPERVISOR_OBSERVATION_DEGRADED ? observation->data.degraded.slot : observation->data.recovered.slot;
	uint64_t cycle_id = observation->type == RESOLVER_SUPERVISOR_OBSERVATION_DEGRADED ? observation->data.degraded.cycle_id : observation->data.recovered.cycle_id;
	if (slot >= RESOLVER_SUPERVISOR_HELPER_COUNT || cycle_id == 0) {
		errno = saved_errno;
		return;
	}
	listener_metrics_helper_log_state *state = &runtime->helper[slot];
	if (state->cycle_id != cycle_id) {
		state->cycle_id = cycle_id;
		state->suppressed = 0;
	}
	char helper_line[LISTENER_METRICS_LINE_SIZE];
	if (observation->type == RESOLVER_SUPERVISOR_OBSERVATION_DEGRADED) {
		const resolver_supervisor_observation_degraded *degraded = &observation->data.degraded;
		if (degraded->failure <= RESOLVER_SUPERVISOR_HELPER_FAILURE_NONE || degraded->failure >= RESOLVER_SUPERVISOR_HELPER_FAILURE_COUNT) {
			errno = saved_errno;
			return;
		}
		if (!listener_metrics_rate_limit_ready(state->degraded_logged_at_valid, &state->degraded_logged_at, processed_at)) {
			listener_metrics_counter_add(&state->suppressed, 1);
			errno = saved_errno;
			return;
		}
		state->degraded_logged_at = *processed_at;
		state->degraded_logged_at_valid = true;
		int length = snprintf(helper_line, sizeof(helper_line),
			"resolver_helper status=degraded slot=%zu pid=%jd failure=%s streak=%" PRIu64 " backoff_ms=%" PRIu64 " suppressed=%" PRIu64,
			degraded->slot, (intmax_t)degraded->process_id, listener_metrics_failure_names[degraded->failure], degraded->failure_count,
			degraded->backoff_milliseconds, state->suppressed);
		if (length < 0 || (size_t)length >= sizeof(helper_line)) {
			listener_metrics_counter_add(&runtime->format_drops, 1);
		} else {
			listener_metrics_helper_line_emit(runtime, log_filename, log_level, MKSYS_LEVEL_WARNING, helper_line);
		}
	} else if (observation->type == RESOLVER_SUPERVISOR_OBSERVATION_RECOVERED) {
		const resolver_supervisor_observation_recovered *recovered = &observation->data.recovered;
		uint64_t degraded_milliseconds;
		if (recovered->recovery >= RESOLVER_SUPERVISOR_HELPER_RECOVERY_COUNT
			|| recovered->last_failure <= RESOLVER_SUPERVISOR_HELPER_FAILURE_NONE || recovered->last_failure >= RESOLVER_SUPERVISOR_HELPER_FAILURE_COUNT
			|| !listener_metrics_duration_milliseconds(&recovered->degraded_at, &recovered->observed_at, &degraded_milliseconds)) {
			listener_metrics_counter_add(&runtime->format_drops, 1);
		} else {
			int length = snprintf(helper_line, sizeof(helper_line),
				"resolver_helper status=recovered slot=%zu pid=%jd recovery=%s degraded_ms=%" PRIu64 " suppressed=%" PRIu64 " last_failure=%s",
				recovered->slot, (intmax_t)recovered->process_id, listener_metrics_recovery_names[recovered->recovery], degraded_milliseconds,
				state->suppressed, listener_metrics_failure_names[recovered->last_failure]);
			if (length < 0 || (size_t)length >= sizeof(helper_line)) {
				listener_metrics_counter_add(&runtime->format_drops, 1);
			} else {
				listener_metrics_helper_line_emit(runtime, log_filename, log_level, MKSYS_LEVEL_INFORMATION, helper_line);
			}
		}
		state->cycle_id = 0;
		state->suppressed = 0;
	}
	errno = saved_errno;
}

void listener_metrics_helper_observation_loss_log(listener_metrics_runtime *runtime, uint64_t observation_dropped, const char *log_filename, uint8_t log_level, const struct timespec *processed_at) {
	int saved_errno = errno;
	if (runtime == NULL || log_filename == NULL || !timeutil_valid(processed_at) || observation_dropped <= runtime->observation_dropped_seen) {
		errno = saved_errno;
		return;
	}
	if (!listener_metrics_rate_limit_ready(runtime->event_loss_logged_at_valid, &runtime->event_loss_logged_at, processed_at)) {
		errno = saved_errno;
		return;
	}
	runtime->observation_dropped_seen = observation_dropped;
	runtime->event_loss_logged_at = *processed_at;
	runtime->event_loss_logged_at_valid = true;
	char helper_line[LISTENER_METRICS_LINE_SIZE];
	int length = snprintf(helper_line, sizeof(helper_line), "resolver_helper status=event_loss dropped=%" PRIu64, observation_dropped);
	if (length < 0 || (size_t)length >= sizeof(helper_line)) {
		listener_metrics_counter_add(&runtime->format_drops, 1);
	} else {
		listener_metrics_helper_line_emit(runtime, log_filename, log_level, MKSYS_LEVEL_WARNING, helper_line);
	}
	errno = saved_errno;
}

void listener_metrics_limits_set(listener_metrics_state *metrics, uint64_t connection_limit, uint64_t worker_limit) {
	if (metrics == NULL) {
		return;
	}
	metrics->connection_limit = connection_limit;
	metrics->worker_limit = worker_limit;
}

void listener_metrics_missed_intervals_record(listener_metrics_runtime *runtime, uint64_t amount) {
	if (runtime != NULL) {
		listener_metrics_counter_add(&runtime->missed_intervals, amount);
	}
}

void listener_metrics_output(listener_metrics_runtime *runtime, listener_metrics_output_reason reason, const listener_metrics_aggregate_snapshot *snapshot,
	const char *log_filename, uint8_t log_level, const struct timespec *now) {
	int saved_errno = errno;
	if (runtime == NULL || reason >= LISTENER_METRICS_OUTPUT_REASON_COUNT || snapshot == NULL || log_filename == NULL || !timeutil_valid(now)) {
		errno = saved_errno;
		return;
	}
	listener_metrics_counter_add(&runtime->sequence, 1);
	const uint64_t sequence = runtime->sequence;
	uint64_t uptime_milliseconds;
	if (!listener_metrics_duration_milliseconds(&runtime->started_at, now, &uptime_milliseconds)) {
		listener_metrics_counter_add(&runtime->format_drops, 1);
		errno = saved_errno;
		return;
	}
	char metrics_line[LISTENER_METRICS_LINE_SIZE];
	listener_metrics_line_builder builder;
	listener_metrics_line_begin(&builder, metrics_line, sizeof(metrics_line), runtime, sequence, "meta");
	(void)listener_metrics_line_append(&builder,
		" reason=%s lines=%u pid=%jd started_mono_sec=%jd started_mono_nsec=%ld uptime_ms=%" PRIu64
		" missed_intervals=%" PRIu64 " scheduler_failures=%" PRIu64 " logger_errors=%" PRIu64 " format_drops=%" PRIu64,
		listener_metrics_output_reason_names[reason], LISTENER_METRICS_LINE_COUNT, (intmax_t)runtime->process_id, (intmax_t)runtime->started_at.tv_sec,
		runtime->started_at.tv_nsec, uptime_milliseconds, runtime->missed_intervals, runtime->scheduler_failures, runtime->logger_errors, runtime->format_drops);
	listener_metrics_line_emit(runtime, log_filename, log_level, &builder, metrics_line);

	const listener_metrics_snapshot *listener = &snapshot->listener;
	listener_metrics_line_begin(&builder, metrics_line, sizeof(metrics_line), runtime, sequence, "listener");
	(void)listener_metrics_line_append(&builder,
		" accepted_total=%" PRIu64 " accept_capacity_rejected_total=%" PRIu64 " accept_fd_exhausted_total=%" PRIu64
		" connection_track_failure_total=%" PRIu64 " connections_current=%" PRIu64 " connections_high_water=%" PRIu64 " connection_limit=%" PRIu64,
		listener->accepted, listener->accept_capacity_rejected, listener->accept_fd_exhausted, listener->connection_track_failure, listener->connections_current,
		listener->connections_high_water, listener->connection_limit);
	(void)listener_metrics_line_append(&builder,
		" worker_spawn_total=%" PRIu64 " worker_fork_failure_total=%" PRIu64 " worker_capacity_refusal_total=%" PRIu64
		" workers_current=%" PRIu64 " workers_high_water=%" PRIu64 " worker_limit=%" PRIu64 " listener_saturation_total=%" PRIu64,
		listener->worker_spawn, listener->worker_fork_failure, listener->worker_capacity_refusal, listener->workers_current, listener->workers_high_water,
		listener->worker_limit, listener->saturation_total);
	listener_metrics_line_emit(runtime, log_filename, log_level, &builder, metrics_line);

	const resolver_cache_metrics_snapshot *cache = &snapshot->cache;
	const resolver_ipc_assembly_metrics_snapshot *assembly = &snapshot->assembly;
	listener_metrics_line_begin(&builder, metrics_line, sizeof(metrics_line), runtime, sequence, "capacity");
	(void)listener_metrics_line_append(&builder,
		" scope=storage cache_entries_current=%" PRIu64 " cache_entries_high_water=%" PRIu64 " cache_entry_limit=%u"
		" cache_owned_bytes_current=%" PRIu64 " cache_owned_bytes_high_water=%" PRIu64 " cache_owned_byte_limit=%u cache_result_byte_limit=%u",
		cache->entries_current, cache->entries_high_water, RESOLVER_CACHE_ENTRY_LIMIT, cache->owned_bytes_current, cache->owned_bytes_high_water,
		RESOLVER_CACHE_OWNED_BYTE_LIMIT, RESOLVER_CACHE_RESULT_BYTE_LIMIT);
	(void)listener_metrics_line_append(&builder,
		" assemblies_nonterminal_current=%" PRIu64 " assembly_owned_bytes_current=%" PRIu64 " assembly_owned_bytes_high_water=%" PRIu64
		" assembly_owned_byte_limit=%u cache_saturation_total=%" PRIu64 " assembly_saturation_total=%" PRIu64,
		assembly->nonterminal_current, assembly->owned_bytes_current, assembly->owned_bytes_high_water, RESOLVER_REPLY_ASSEMBLY_BYTE_LIMIT,
		cache->saturation_total, assembly->saturation_total);
	listener_metrics_line_emit(runtime, log_filename, log_level, &builder, metrics_line);

	const resolver_supervisor_metrics_snapshot *supervisor = &snapshot->supervisor;
	listener_metrics_line_begin(&builder, metrics_line, sizeof(metrics_line), runtime, sequence, "capacity");
	(void)listener_metrics_line_append(&builder,
		" scope=supervisor jobs_current=%" PRIu64 " jobs_high_water=%" PRIu64 " job_limit=%u interactive_reserve=%u"
		" jobs_queued=%" PRIu64 " jobs_sending=%" PRIu64 " jobs_dispatched=%" PRIu64 " jobs_retry_wait=%" PRIu64 " jobs_complete=%" PRIu64,
		supervisor->jobs_current, supervisor->jobs_high_water, RESOLVER_SUPERVISOR_JOB_LIMIT, RESOLVER_SUPERVISOR_INTERACTIVE_RESERVE,
		supervisor->jobs_state_current[RESOLVER_SUPERVISOR_JOB_QUEUED], supervisor->jobs_state_current[RESOLVER_SUPERVISOR_JOB_SENDING],
		supervisor->jobs_state_current[RESOLVER_SUPERVISOR_JOB_DISPATCHED], supervisor->jobs_state_current[RESOLVER_SUPERVISOR_JOB_RETRY_WAIT],
		supervisor->jobs_state_current[RESOLVER_SUPERVISOR_JOB_COMPLETE]);
	(void)listener_metrics_line_append(&builder,
		" jobs_background=%" PRIu64 " jobs_interactive=%" PRIu64 " orphaned_dispatched_current=%" PRIu64
		" queue_background_current=%" PRIu64 " queue_background_high_water=%" PRIu64 " queue_interactive_current=%" PRIu64
		" queue_interactive_high_water=%" PRIu64 " interests_background_current=%" PRIu64 " interests_interactive_current=%" PRIu64
		" helper_limit=%u supervisor_saturation_total=%" PRIu64,
		supervisor->jobs_priority_current[RESOLVER_SUPERVISOR_PRIORITY_BACKGROUND], supervisor->jobs_priority_current[RESOLVER_SUPERVISOR_PRIORITY_INTERACTIVE],
		supervisor->orphaned_dispatched_current, supervisor->queue_current[RESOLVER_SUPERVISOR_PRIORITY_BACKGROUND],
		supervisor->queue_high_water[RESOLVER_SUPERVISOR_PRIORITY_BACKGROUND], supervisor->queue_current[RESOLVER_SUPERVISOR_PRIORITY_INTERACTIVE],
		supervisor->queue_high_water[RESOLVER_SUPERVISOR_PRIORITY_INTERACTIVE], supervisor->interests_current[RESOLVER_SUPERVISOR_PRIORITY_BACKGROUND],
		supervisor->interests_current[RESOLVER_SUPERVISOR_PRIORITY_INTERACTIVE], RESOLVER_SUPERVISOR_HELPER_COUNT, supervisor->saturation_total);
	listener_metrics_line_emit(runtime, log_filename, log_level, &builder, metrics_line);

	for (size_t priority = 0; priority < RESOLVER_SUPERVISOR_PRIORITY_COUNT; priority++) {
		for (size_t query = 0; query < METRICS_QUERY_TYPE_COUNT; query++) {
			const resolver_supervisor_metrics_schedule *schedule = &supervisor->schedule[priority][query];
			listener_metrics_line_begin(&builder, metrics_line, sizeof(metrics_line), runtime, sequence, "schedule");
			(void)listener_metrics_line_append(&builder,
				" priority=%s qtype=%s started=%" PRIu64 " coalesced=%" PRIu64 " complete=%" PRIu64 " fresh=%" PRIu64
				" bad_argument=%" PRIu64 " io=%" PRIu64 " limit=%" PRIu64 " memory=%" PRIu64 " time=%" PRIu64,
				listener_metrics_priority_names[priority], listener_metrics_query_type_names[query], schedule->status[RESOLVER_SUPERVISOR_SCHEDULE_STARTED],
				schedule->status[RESOLVER_SUPERVISOR_SCHEDULE_COALESCED], schedule->status[RESOLVER_SUPERVISOR_SCHEDULE_COMPLETE],
				schedule->status[RESOLVER_SUPERVISOR_SCHEDULE_FRESH], schedule->status[RESOLVER_SUPERVISOR_SCHEDULE_BAD_ARGUMENT],
				schedule->status[RESOLVER_SUPERVISOR_SCHEDULE_IO], schedule->status[RESOLVER_SUPERVISOR_SCHEDULE_LIMIT],
				schedule->status[RESOLVER_SUPERVISOR_SCHEDULE_MEMORY], schedule->status[RESOLVER_SUPERVISOR_SCHEDULE_TIME]);
			(void)listener_metrics_line_append(&builder,
				" limit_interest_count=%" PRIu64 " limit_background_admission=%" PRIu64 " limit_total_admission=%" PRIu64
				" limit_entry_reference=%" PRIu64,
				schedule->limit_interest_count, schedule->limit_background_admission, schedule->limit_total_admission, schedule->limit_entry_reference);
			listener_metrics_line_emit(runtime, log_filename, log_level, &builder, metrics_line);
		}
	}

	for (size_t query = 0; query < METRICS_RESOLVER_QUERY_TYPE_COUNT; query++) {
		const resolver_supervisor_metrics_attempt *attempt = &supervisor->attempt[query];
		listener_metrics_line_begin(&builder, metrics_line, sizeof(metrics_line), runtime, sequence, "attempt");
		(void)listener_metrics_line_append(&builder,
			" qtype=%s dispatched=%" PRIu64 " response_ok=%" PRIu64 " response_bad_argument=%" PRIu64 " response_limit=%" PRIu64
			" response_malformed=%" PRIu64 " response_memory=%" PRIu64 " response_nodata=%" PRIu64 " response_not_found=%" PRIu64
			" response_permanent=%" PRIu64 " response_temporary=%" PRIu64 " response_truncated=%" PRIu64,
			listener_metrics_query_type_names[query], attempt->dispatched, attempt->response[RESOLVER_SUPERVISOR_DNS_OUTCOME_OK],
			attempt->response[RESOLVER_SUPERVISOR_DNS_OUTCOME_BAD_ARGUMENT], attempt->response[RESOLVER_SUPERVISOR_DNS_OUTCOME_LIMIT],
			attempt->response[RESOLVER_SUPERVISOR_DNS_OUTCOME_MALFORMED], attempt->response[RESOLVER_SUPERVISOR_DNS_OUTCOME_MEMORY],
			attempt->response[RESOLVER_SUPERVISOR_DNS_OUTCOME_NODATA], attempt->response[RESOLVER_SUPERVISOR_DNS_OUTCOME_NOT_FOUND],
			attempt->response[RESOLVER_SUPERVISOR_DNS_OUTCOME_PERMANENT], attempt->response[RESOLVER_SUPERVISOR_DNS_OUTCOME_TEMPORARY],
			attempt->response[RESOLVER_SUPERVISOR_DNS_OUTCOME_TRUNCATED]);
		(void)listener_metrics_line_append(&builder,
			" failure_exit=%" PRIu64 " failure_io=%" PRIu64 " failure_protocol=%" PRIu64 " failure_timeout=%" PRIu64
			" retry_scheduled=%" PRIu64 " orphan_response_ok=%" PRIu64 " orphan_response_bad_argument=%" PRIu64 " orphan_response_limit=%" PRIu64
			" orphan_response_malformed=%" PRIu64 " orphan_response_memory=%" PRIu64 " orphan_response_nodata=%" PRIu64,
			attempt->failure[RESOLVER_SUPERVISOR_HELPER_FAILURE_EXIT], attempt->failure[RESOLVER_SUPERVISOR_HELPER_FAILURE_IO],
			attempt->failure[RESOLVER_SUPERVISOR_HELPER_FAILURE_PROTOCOL], attempt->failure[RESOLVER_SUPERVISOR_HELPER_FAILURE_TIMEOUT], attempt->retry_scheduled,
			attempt->orphan_response[RESOLVER_SUPERVISOR_DNS_OUTCOME_OK], attempt->orphan_response[RESOLVER_SUPERVISOR_DNS_OUTCOME_BAD_ARGUMENT],
			attempt->orphan_response[RESOLVER_SUPERVISOR_DNS_OUTCOME_LIMIT], attempt->orphan_response[RESOLVER_SUPERVISOR_DNS_OUTCOME_MALFORMED],
			attempt->orphan_response[RESOLVER_SUPERVISOR_DNS_OUTCOME_MEMORY], attempt->orphan_response[RESOLVER_SUPERVISOR_DNS_OUTCOME_NODATA]);
		(void)listener_metrics_line_append(&builder,
			" orphan_response_not_found=%" PRIu64 " orphan_response_permanent=%" PRIu64 " orphan_response_temporary=%" PRIu64
			" orphan_response_truncated=%" PRIu64 " completion_enqueued=%" PRIu64 " completion_taken=%" PRIu64
			" attempt_abandoned_shutdown=%" PRIu64 " completion_abandoned_shutdown=%" PRIu64 " jobs_dispatched_current=%" PRIu64
			" jobs_complete_current=%" PRIu64,
			attempt->orphan_response[RESOLVER_SUPERVISOR_DNS_OUTCOME_NOT_FOUND], attempt->orphan_response[RESOLVER_SUPERVISOR_DNS_OUTCOME_PERMANENT],
			attempt->orphan_response[RESOLVER_SUPERVISOR_DNS_OUTCOME_TEMPORARY], attempt->orphan_response[RESOLVER_SUPERVISOR_DNS_OUTCOME_TRUNCATED],
			attempt->completion_enqueued, attempt->completion_taken, attempt->attempt_abandoned_shutdown, attempt->completion_abandoned_shutdown,
			attempt->jobs_dispatched_current, attempt->jobs_complete_current);
		listener_metrics_line_emit(runtime, log_filename, log_level, &builder, metrics_line);
	}

	for (size_t query = 0; query < METRICS_QUERY_TYPE_COUNT; query++) {
		const resolver_cache_metrics_query *entry = &cache->query[query];
		listener_metrics_line_begin(&builder, metrics_line, sizeof(metrics_line), runtime, sequence, "cache");
		(void)listener_metrics_line_append(&builder,
			" qtype=%s acquire_created=%" PRIu64 " acquire_reused=%" PRIu64 " acquire_bad_argument=%" PRIu64
			" acquire_reference_limit=%" PRIu64 " acquire_entry_limit=%" PRIu64 " acquire_id_limit=%" PRIu64
			" acquire_owned_byte_limit=%" PRIu64 " acquire_memory=%" PRIu64,
			listener_metrics_query_type_names[query], entry->acquire_created, entry->acquire_reused, entry->acquire_bad_argument, entry->acquire_reference_limit,
			entry->acquire_entry_limit, entry->acquire_id_limit, entry->acquire_owned_byte_limit, entry->acquire_memory);
		(void)listener_metrics_line_append(&builder,
			" publish_stored=%" PRIu64 " publish_transient=%" PRIu64 " publish_bad_argument=%" PRIu64 " publish_invalid=%" PRIu64
			" publish_limit=%" PRIu64 " publish_memory=%" PRIu64 " publish_time=%" PRIu64 " publish_limit_result_bytes=%" PRIu64
			" publish_limit_owned_bytes=%" PRIu64,
			entry->publish_stored, entry->publish_transient, entry->publish_bad_argument, entry->publish_invalid, entry->publish_limit, entry->publish_memory,
			entry->publish_time, entry->publish_limit_result_bytes, entry->publish_limit_owned_bytes);
		(void)listener_metrics_line_append(&builder,
			" value_positive=%" PRIu64 " value_nxdomain=%" PRIu64 " value_nodata=%" PRIu64 " expiry_positive=%" PRIu64
			" expiry_nxdomain=%" PRIu64 " expiry_nodata=%" PRIu64 " resident_positive=%" PRIu64 " resident_nxdomain=%" PRIu64
			" resident_nodata=%" PRIu64,
			entry->value_positive, entry->value_nxdomain, entry->value_nodata, entry->expiry_positive, entry->expiry_nxdomain, entry->expiry_nodata,
			entry->resident_positive, entry->resident_nxdomain, entry->resident_nodata);
		listener_metrics_line_emit(runtime, log_filename, log_level, &builder, metrics_line);
	}

	for (size_t query = 0; query < METRICS_RESOLVER_QUERY_TYPE_COUNT; query++) {
		const resolver_ipc_assembly_metrics_query *item = &assembly->query[query];
		listener_metrics_line_begin(&builder, metrics_line, sizeof(metrics_line), runtime, sequence, "assembly");
		(void)listener_metrics_line_append(&builder,
			" qtype=%s create_ok=%" PRIu64 " create_bad_argument=%" PRIu64 " create_limit=%" PRIu64 " create_memory=%" PRIu64
			" limit_result_shape=%" PRIu64 " limit_result_bytes=%" PRIu64 " limit_budget_bytes=%" PRIu64 " terminal_complete=%" PRIu64
			" terminal_bad_argument=%" PRIu64 " terminal_limit=%" PRIu64 " terminal_memory=%" PRIu64 " terminal_protocol=%" PRIu64
			" abandoned=%" PRIu64 " nonterminal_current=%" PRIu64,
			listener_metrics_query_type_names[query], item->create_ok, item->create_bad_argument, item->create_limit, item->create_memory, item->limit_result_shape,
			item->limit_result_bytes, item->limit_budget_bytes, item->terminal_complete, item->terminal_bad_argument, item->terminal_limit, item->terminal_memory,
			item->terminal_protocol, item->abandoned, item->nonterminal_current);
		listener_metrics_line_emit(runtime, log_filename, log_level, &builder, metrics_line);
	}

	for (size_t mode = 0; mode < LISTENER_METRICS_REQUEST_COUNT; mode++) {
		const listener_metrics_route *route = &listener->route[mode];
		listener_metrics_line_begin(&builder, metrics_line, sizeof(metrics_line), runtime, sequence, "route");
		(void)listener_metrics_line_append(&builder,
			" request_mode=%s requests_started=%" PRIu64 " resolution_local=%" PRIu64 " resolution_bypass=%" PRIu64
			" resolution_immediate=%" PRIu64 " resolution_waited=%" PRIu64 " outcome_ready=%" PRIu64 " outcome_contradictory=%" PRIu64
			" outcome_limit=%" PRIu64 " outcome_memory=%" PRIu64 " outcome_no_route=%" PRIu64,
			listener_metrics_request_mode_names[mode], route->requests_started, route->resolution[LISTENER_METRICS_RESOLUTION_LOCAL],
			route->resolution[LISTENER_METRICS_RESOLUTION_BYPASS], route->resolution[LISTENER_METRICS_RESOLUTION_IMMEDIATE],
			route->resolution[LISTENER_METRICS_RESOLUTION_WAITED], route->outcome[LISTENER_METRICS_OUTCOME_READY],
			route->outcome[LISTENER_METRICS_OUTCOME_CONTRADICTORY], route->outcome[LISTENER_METRICS_OUTCOME_LIMIT],
			route->outcome[LISTENER_METRICS_OUTCOME_MEMORY], route->outcome[LISTENER_METRICS_OUTCOME_NO_ROUTE]);
		(void)listener_metrics_line_append(&builder,
			" outcome_service_unavailable=%" PRIu64 " outcome_timeout=%" PRIu64 " outcome_unavailable=%" PRIu64
			" outcome_abandoned=%" PRIu64 " outcome_shutdown=%" PRIu64 " outcome_internal_error=%" PRIu64 " pending_current=%" PRIu64
			" pending_high_water=%" PRIu64 " release_failure=%" PRIu64 " selected_ipv4=%" PRIu64 " selected_ipv6=%" PRIu64,
			route->outcome[LISTENER_METRICS_OUTCOME_SERVICE_UNAVAILABLE], route->outcome[LISTENER_METRICS_OUTCOME_TIMEOUT],
			route->outcome[LISTENER_METRICS_OUTCOME_UNAVAILABLE], route->outcome[LISTENER_METRICS_OUTCOME_ABANDONED],
			route->outcome[LISTENER_METRICS_OUTCOME_SHUTDOWN], route->outcome[LISTENER_METRICS_OUTCOME_INTERNAL_ERROR], route->pending_current,
			route->pending_high_water, route->release_failure, route->selected_family[LISTENER_METRICS_SELECTED_FAMILY_IPV4],
			route->selected_family[LISTENER_METRICS_SELECTED_FAMILY_IPV6]);
		listener_metrics_line_emit(runtime, log_filename, log_level, &builder, metrics_line);
	}

	listener_metrics_line_begin(&builder, metrics_line, sizeof(metrics_line), runtime, sequence, "helper");
	(void)listener_metrics_line_append(&builder,
		" failure_exit=%" PRIu64 " failure_io=%" PRIu64 " failure_protocol=%" PRIu64 " failure_spawn=%" PRIu64
		" failure_timeout=%" PRIu64 " spawn_attempt=%" PRIu64 " spawn_success=%" PRIu64 " recovery_success_streak=%" PRIu64
		" recovery_stable_uptime=%" PRIu64 " observation_dropped=%" PRIu64,
		supervisor->helper.failure[RESOLVER_SUPERVISOR_HELPER_FAILURE_EXIT], supervisor->helper.failure[RESOLVER_SUPERVISOR_HELPER_FAILURE_IO],
		supervisor->helper.failure[RESOLVER_SUPERVISOR_HELPER_FAILURE_PROTOCOL], supervisor->helper.failure[RESOLVER_SUPERVISOR_HELPER_FAILURE_SPAWN],
		supervisor->helper.failure[RESOLVER_SUPERVISOR_HELPER_FAILURE_TIMEOUT], supervisor->helper.spawn_attempt, supervisor->helper.spawn_success,
		supervisor->helper.recovery[RESOLVER_SUPERVISOR_HELPER_RECOVERY_SUCCESS_STREAK], supervisor->helper.recovery[RESOLVER_SUPERVISOR_HELPER_RECOVERY_STABLE_UPTIME],
		supervisor->helper.observation_dropped);
	(void)listener_metrics_line_append(&builder,
		" state_idle=%" PRIu64 " state_sending=%" PRIu64 " state_busy=%" PRIu64 " state_backoff=%" PRIu64
		" state_shutting_down=%" PRIu64 " state_stopped=%" PRIu64,
		supervisor->helper.state_current[RESOLVER_SUPERVISOR_HELPER_IDLE], supervisor->helper.state_current[RESOLVER_SUPERVISOR_HELPER_SENDING],
		supervisor->helper.state_current[RESOLVER_SUPERVISOR_HELPER_BUSY], supervisor->helper.state_current[RESOLVER_SUPERVISOR_HELPER_BACKOFF],
		supervisor->helper.state_current[RESOLVER_SUPERVISOR_HELPER_SHUTTING_DOWN], supervisor->helper.state_current[RESOLVER_SUPERVISOR_HELPER_STOPPED]);
	listener_metrics_line_emit(runtime, log_filename, log_level, &builder, metrics_line);

	for (size_t priority = 0; priority < RESOLVER_SUPERVISOR_PRIORITY_COUNT; priority++) {
		for (size_t query = 0; query < METRICS_RESOLVER_QUERY_TYPE_COUNT; query++) {
			const metrics_histogram_snapshot *histogram = &supervisor->dispatch_wait[priority][query];
			listener_metrics_line_begin(&builder, metrics_line, sizeof(metrics_line), runtime, sequence, "histogram");
			(void)listener_metrics_line_append(&builder,
				" name=dispatch_wait_ms priority=%s qtype=%s le_1=%" PRIu64 " le_5=%" PRIu64 " le_10=%" PRIu64 " le_25=%" PRIu64
				" le_50=%" PRIu64 " le_100=%" PRIu64 " le_250=%" PRIu64 " le_500=%" PRIu64,
				listener_metrics_priority_names[priority], listener_metrics_query_type_names[query], histogram->cumulative[0], histogram->cumulative[1],
				histogram->cumulative[2], histogram->cumulative[3], histogram->cumulative[4], histogram->cumulative[5], histogram->cumulative[6],
				histogram->cumulative[7]);
			(void)listener_metrics_line_append(&builder,
				" le_1000=%" PRIu64 " le_2000=%" PRIu64 " le_5000=%" PRIu64 " le_10000=%" PRIu64 " le_30000=%" PRIu64
				" le_inf=%" PRIu64 " count=%" PRIu64 " sum_us=%" PRIu64 " sample_errors=%" PRIu64,
				histogram->cumulative[8], histogram->cumulative[9], histogram->cumulative[10], histogram->cumulative[11], histogram->cumulative[12],
				histogram->cumulative[13], histogram->count, histogram->sum, histogram->sample_errors);
			listener_metrics_line_emit(runtime, log_filename, log_level, &builder, metrics_line);
		}
	}

	for (size_t query = 0; query < METRICS_RESOLVER_QUERY_TYPE_COUNT; query++) {
		const metrics_histogram_snapshot *histogram = &supervisor->attempt_duration[query];
		listener_metrics_line_begin(&builder, metrics_line, sizeof(metrics_line), runtime, sequence, "histogram");
		(void)listener_metrics_line_append(&builder,
			" name=attempt_ms qtype=%s le_1=%" PRIu64 " le_5=%" PRIu64 " le_10=%" PRIu64 " le_25=%" PRIu64 " le_50=%" PRIu64
			" le_100=%" PRIu64 " le_250=%" PRIu64 " le_500=%" PRIu64 " le_1000=%" PRIu64 " le_2000=%" PRIu64,
			listener_metrics_query_type_names[query], histogram->cumulative[0], histogram->cumulative[1], histogram->cumulative[2], histogram->cumulative[3],
			histogram->cumulative[4], histogram->cumulative[5], histogram->cumulative[6], histogram->cumulative[7], histogram->cumulative[8], histogram->cumulative[9]);
		(void)listener_metrics_line_append(&builder,
			" le_5000=%" PRIu64 " le_10000=%" PRIu64 " le_30000=%" PRIu64 " le_inf=%" PRIu64 " count=%" PRIu64
			" sum_us=%" PRIu64 " sample_errors=%" PRIu64,
			histogram->cumulative[10], histogram->cumulative[11], histogram->cumulative[12], histogram->cumulative[13], histogram->count, histogram->sum,
			histogram->sample_errors);
		listener_metrics_line_emit(runtime, log_filename, log_level, &builder, metrics_line);
	}

	for (size_t query = 0; query < METRICS_RESOLVER_QUERY_TYPE_COUNT; query++) {
		for (size_t payload = 0; payload < METRICS_PAYLOAD_KIND_COUNT; payload++) {
			const metrics_histogram_snapshot *histogram = &cache->ttl[query][payload];
			listener_metrics_line_begin(&builder, metrics_line, sizeof(metrics_line), runtime, sequence, "histogram");
			(void)listener_metrics_line_append(&builder,
				" name=ttl_seconds qtype=%s payload_kind=%s le_0=%" PRIu64 " le_1=%" PRIu64 " le_5=%" PRIu64 " le_30=%" PRIu64
				" le_60=%" PRIu64 " le_300=%" PRIu64 " le_1800=%" PRIu64 " le_3600=%" PRIu64,
				listener_metrics_query_type_names[query], listener_metrics_payload_kind_names[payload], histogram->cumulative[0], histogram->cumulative[1],
				histogram->cumulative[2], histogram->cumulative[3], histogram->cumulative[4], histogram->cumulative[5], histogram->cumulative[6],
				histogram->cumulative[7]);
			(void)listener_metrics_line_append(&builder,
				" le_21600=%" PRIu64 " le_86400=%" PRIu64 " le_604800=%" PRIu64 " le_2592000=%" PRIu64 " le_inf=%" PRIu64
				" count=%" PRIu64 " sum_seconds=%" PRIu64,
				histogram->cumulative[8], histogram->cumulative[9], histogram->cumulative[10], histogram->cumulative[11], histogram->cumulative[12],
				histogram->count, histogram->sum);
			listener_metrics_line_emit(runtime, log_filename, log_level, &builder, metrics_line);
		}
	}

	for (size_t query = 0; query < METRICS_RESOLVER_QUERY_TYPE_COUNT; query++) {
		const metrics_histogram_snapshot *histogram = &assembly->result_size[query];
		listener_metrics_line_begin(&builder, metrics_line, sizeof(metrics_line), runtime, sequence, "histogram");
		(void)listener_metrics_line_append(&builder,
			" name=assembly_bytes qtype=%s le_0=%" PRIu64 " le_64=%" PRIu64 " le_256=%" PRIu64 " le_1024=%" PRIu64
			" le_4096=%" PRIu64 " le_16384=%" PRIu64 " le_65536=%" PRIu64 " le_262144=%" PRIu64 " le_1048576=%" PRIu64
			" le_inf=%" PRIu64 " count=%" PRIu64 " sum_bytes=%" PRIu64,
			listener_metrics_query_type_names[query], histogram->cumulative[0], histogram->cumulative[1], histogram->cumulative[2], histogram->cumulative[3],
			histogram->cumulative[4], histogram->cumulative[5], histogram->cumulative[6], histogram->cumulative[7], histogram->cumulative[8],
			histogram->cumulative[9], histogram->count, histogram->sum);
		listener_metrics_line_emit(runtime, log_filename, log_level, &builder, metrics_line);
	}

	for (size_t mode = 0; mode < LISTENER_METRICS_REQUEST_COUNT; mode++) {
		const metrics_histogram_snapshot *histogram = &listener->route_duration[mode];
		listener_metrics_line_begin(&builder, metrics_line, sizeof(metrics_line), runtime, sequence, "histogram");
		(void)listener_metrics_line_append(&builder,
			" name=route_ms request_mode=%s le_1=%" PRIu64 " le_5=%" PRIu64 " le_10=%" PRIu64 " le_25=%" PRIu64 " le_50=%" PRIu64
			" le_100=%" PRIu64 " le_250=%" PRIu64 " le_500=%" PRIu64 " le_1000=%" PRIu64 " le_2000=%" PRIu64,
			listener_metrics_request_mode_names[mode], histogram->cumulative[0], histogram->cumulative[1], histogram->cumulative[2], histogram->cumulative[3],
			histogram->cumulative[4], histogram->cumulative[5], histogram->cumulative[6], histogram->cumulative[7], histogram->cumulative[8], histogram->cumulative[9]);
		(void)listener_metrics_line_append(&builder,
			" le_5000=%" PRIu64 " le_10000=%" PRIu64 " le_30000=%" PRIu64 " le_inf=%" PRIu64 " count=%" PRIu64
			" sum_us=%" PRIu64 " sample_errors=%" PRIu64,
			histogram->cumulative[10], histogram->cumulative[11], histogram->cumulative[12], histogram->cumulative[13], histogram->count, histogram->sum,
			histogram->sample_errors);
		listener_metrics_line_emit(runtime, log_filename, log_level, &builder, metrics_line);
	}
	errno = saved_errno;
}

bool listener_metrics_route_duration_enable(listener_metrics_route_request *request) {
	if (request == NULL || !request->started || request->settled) {
		return false;
	}
	request->duration_enabled = true;
	return true;
}

bool listener_metrics_route_pending(listener_metrics_state *metrics, listener_metrics_route_request *request) {
	if (metrics == NULL || request == NULL || !request->started || request->settled || request->pending || request->mode >= LISTENER_METRICS_REQUEST_COUNT) {
		return false;
	}
	listener_metrics_route *route = &metrics->route[request->mode];
	listener_metrics_increment(metrics, &route->pending_current);
	metrics_high_water_update(&route->pending_high_water, route->pending_current);
	request->pending = true;
	return true;
}

bool listener_metrics_route_release_failure_record(listener_metrics_state *metrics, const listener_metrics_route_request *request) {
	if (metrics == NULL || request == NULL || !request->started || request->mode >= LISTENER_METRICS_REQUEST_COUNT) {
		return false;
	}
	listener_metrics_increment(metrics, &metrics->route[request->mode].release_failure);
	return true;
}

bool listener_metrics_route_resolution_record(listener_metrics_state *metrics, listener_metrics_route_request *request, listener_metrics_resolution resolution) {
	if (metrics == NULL || request == NULL || !request->started || request->settled || request->resolution_recorded
		|| request->mode >= LISTENER_METRICS_REQUEST_COUNT || resolution >= LISTENER_METRICS_RESOLUTION_COUNT) {
		return false;
	}
	listener_metrics_increment(metrics, &metrics->route[request->mode].resolution[resolution]);
	request->resolution_recorded = true;
	return true;
}

bool listener_metrics_route_settle(listener_metrics_state *metrics, listener_metrics_route_request *request, listener_metrics_outcome outcome,
	listener_metrics_selected_family selected_family, const struct timespec *now) {
	if (metrics == NULL || request == NULL || !request->started || request->settled || request->mode >= LISTENER_METRICS_REQUEST_COUNT
		|| outcome >= LISTENER_METRICS_OUTCOME_COUNT || selected_family < LISTENER_METRICS_SELECTED_FAMILY_NONE
		|| selected_family >= LISTENER_METRICS_SELECTED_FAMILY_COUNT) {
		return false;
	}
	listener_metrics_route *route = &metrics->route[request->mode];
	listener_metrics_increment(metrics, &route->outcome[outcome]);
	if (request->pending) {
		listener_metrics_decrement(metrics, &route->pending_current);
		request->pending = false;
	}
	if (request->duration_enabled) {
		(void)metrics_duration_histogram_observe(&metrics->route_duration[request->mode], &request->started_at, now, &metrics->saturation_total);
	}
	if (outcome == LISTENER_METRICS_OUTCOME_READY && selected_family != LISTENER_METRICS_SELECTED_FAMILY_NONE) {
		listener_metrics_increment(metrics, &route->selected_family[selected_family]);
	}
	request->settled = true;
	return true;
}

bool listener_metrics_route_start(listener_metrics_state *metrics, listener_metrics_route_request *request, listener_metrics_request_mode mode, const struct timespec *now) {
	if (metrics == NULL || request == NULL || request->started || mode >= LISTENER_METRICS_REQUEST_COUNT || now == NULL) {
		return false;
	}
	request->mode = mode;
	request->started = true;
	request->started_at = *now;
	listener_metrics_increment(metrics, &metrics->route[mode].requests_started);
	return true;
}

bool listener_metrics_runtime_init(listener_metrics_runtime *runtime, pid_t process_id, const struct timespec *started_at) {
	if (runtime == NULL || process_id <= 0 || !timeutil_valid(started_at)) {
		return false;
	}
	memset(runtime, 0, sizeof(*runtime));
	runtime->process_id = process_id;
	runtime->started_at = *started_at;
	return true;
}

void listener_metrics_scheduler_failure_record(listener_metrics_runtime *runtime) {
	if (runtime != NULL) {
		listener_metrics_counter_add(&runtime->scheduler_failures, 1);
	}
}

bool listener_metrics_snapshot_get(const listener_metrics_state *metrics, listener_metrics_snapshot *result) {
	if (metrics == NULL || result == NULL) {
		return false;
	}
	memset(result, 0, sizeof(*result));
	result->accept_capacity_rejected = metrics->accept_capacity_rejected;
	result->accept_fd_exhausted = metrics->accept_fd_exhausted;
	result->accepted = metrics->accepted;
	result->connection_limit = metrics->connection_limit;
	result->connection_track_failure = metrics->connection_track_failure;
	result->connections_current = metrics->connections_current;
	result->connections_high_water = metrics->connections_high_water;
	memcpy(result->route, metrics->route, sizeof(result->route));
	for (size_t mode = 0; mode < LISTENER_METRICS_REQUEST_COUNT; mode++) {
		metrics_duration_histogram_get(&metrics->route_duration[mode], &result->route_duration[mode]);
	}
	result->saturation_total = metrics->saturation_total;
	result->worker_capacity_refusal = metrics->worker_capacity_refusal;
	result->worker_fork_failure = metrics->worker_fork_failure;
	result->worker_limit = metrics->worker_limit;
	result->worker_spawn = metrics->worker_spawn;
	result->workers_current = metrics->workers_current;
	result->workers_high_water = metrics->workers_high_water;
	return true;
}

void listener_metrics_worker_add(listener_metrics_state *metrics) {
	if (metrics == NULL) {
		return;
	}
	listener_metrics_increment(metrics, &metrics->worker_spawn);
	listener_metrics_increment(metrics, &metrics->workers_current);
	metrics_high_water_update(&metrics->workers_high_water, metrics->workers_current);
}

void listener_metrics_worker_capacity_refusal_record(listener_metrics_state *metrics) {
	if (metrics != NULL) {
		listener_metrics_increment(metrics, &metrics->worker_capacity_refusal);
	}
}

void listener_metrics_worker_fork_failure_record(listener_metrics_state *metrics) {
	if (metrics != NULL) {
		listener_metrics_increment(metrics, &metrics->worker_fork_failure);
	}
}

void listener_metrics_worker_remove(listener_metrics_state *metrics) {
	if (metrics != NULL) {
		listener_metrics_decrement(metrics, &metrics->workers_current);
	}
}
