/*
 * listener_metrics.h: Listener-owned capacity and route metrics
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Bilin Tsui
 */

#ifndef _MRS_LISTENER_METRICS_H_INCLUDED_

#define _MRS_LISTENER_METRICS_H_INCLUDED_

/* section: headers (library) */
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

/* section: headers (project) */
#include "config.h"
#include "metrics.h"
#include "resolver/cache.h"
#include "resolver/ipc_assembly.h"
#include "resolver/supervisor.h"

/* section: defines */
#define LISTENER_METRICS_LINE_COUNT	48U
#define LISTENER_METRICS_LINE_SIZE	2049U

/* section: types */
typedef enum {
	LISTENER_METRICS_OUTCOME_READY,
	LISTENER_METRICS_OUTCOME_CONTRADICTORY,
	LISTENER_METRICS_OUTCOME_LIMIT,
	LISTENER_METRICS_OUTCOME_MEMORY,
	LISTENER_METRICS_OUTCOME_NO_ROUTE,
	LISTENER_METRICS_OUTCOME_SERVICE_UNAVAILABLE,
	LISTENER_METRICS_OUTCOME_TIMEOUT,
	LISTENER_METRICS_OUTCOME_UNAVAILABLE,
	LISTENER_METRICS_OUTCOME_ABANDONED,
	LISTENER_METRICS_OUTCOME_SHUTDOWN,
	LISTENER_METRICS_OUTCOME_INTERNAL_ERROR,
	LISTENER_METRICS_OUTCOME_COUNT
} listener_metrics_outcome;
typedef enum {
	LISTENER_METRICS_REQUEST_SHORT,
	LISTENER_METRICS_REQUEST_WORKER,
	LISTENER_METRICS_REQUEST_COUNT
} listener_metrics_request_mode;
typedef enum {
	LISTENER_METRICS_RESOLUTION_LOCAL,
	LISTENER_METRICS_RESOLUTION_BYPASS,
	LISTENER_METRICS_RESOLUTION_IMMEDIATE,
	LISTENER_METRICS_RESOLUTION_WAITED,
	LISTENER_METRICS_RESOLUTION_COUNT
} listener_metrics_resolution;
typedef enum {
	LISTENER_METRICS_SELECTED_FAMILY_NONE = -1,
	LISTENER_METRICS_SELECTED_FAMILY_IPV4,
	LISTENER_METRICS_SELECTED_FAMILY_IPV6,
	LISTENER_METRICS_SELECTED_FAMILY_COUNT
} listener_metrics_selected_family;
typedef enum {
	LISTENER_METRICS_OUTPUT_STARTUP,
	LISTENER_METRICS_OUTPUT_PERIODIC,
	LISTENER_METRICS_OUTPUT_RECONFIGURE,
	LISTENER_METRICS_OUTPUT_DISABLE,
	LISTENER_METRICS_OUTPUT_SHUTDOWN,
	LISTENER_METRICS_OUTPUT_REASON_COUNT
} listener_metrics_output_reason;
typedef struct {
	uint64_t outcome[LISTENER_METRICS_OUTCOME_COUNT];
	uint64_t pending_current;
	uint64_t pending_high_water;
	uint64_t release_failure;
	uint64_t requests_started;
	uint64_t resolution[LISTENER_METRICS_RESOLUTION_COUNT];
	uint64_t selected_family[LISTENER_METRICS_SELECTED_FAMILY_COUNT];
} listener_metrics_route;
typedef struct {
	bool duration_enabled;
	listener_metrics_request_mode mode;
	bool pending;
	bool resolution_recorded;
	bool settled;
	struct timespec started_at;
	bool started;
} listener_metrics_route_request;
typedef struct {
	uint64_t accept_capacity_rejected;
	uint64_t accept_fd_exhausted;
	uint64_t accepted;
	uint64_t connection_limit;
	uint64_t connection_track_failure;
	uint64_t connections_current;
	uint64_t connections_high_water;
	listener_metrics_route route[LISTENER_METRICS_REQUEST_COUNT];
	metrics_histogram route_duration[LISTENER_METRICS_REQUEST_COUNT];
	uint64_t saturation_total;
	uint64_t worker_capacity_refusal;
	uint64_t worker_fork_failure;
	uint64_t worker_limit;
	uint64_t worker_spawn;
	uint64_t workers_current;
	uint64_t workers_high_water;
} listener_metrics_state;
typedef struct {
	uint64_t accept_capacity_rejected;
	uint64_t accept_fd_exhausted;
	uint64_t accepted;
	uint64_t connection_limit;
	uint64_t connection_track_failure;
	uint64_t connections_current;
	uint64_t connections_high_water;
	listener_metrics_route route[LISTENER_METRICS_REQUEST_COUNT];
	metrics_histogram_snapshot route_duration[LISTENER_METRICS_REQUEST_COUNT];
	uint64_t saturation_total;
	uint64_t worker_capacity_refusal;
	uint64_t worker_fork_failure;
	uint64_t worker_limit;
	uint64_t worker_spawn;
	uint64_t workers_current;
	uint64_t workers_high_water;
} listener_metrics_snapshot;
typedef struct {
	resolver_ipc_assembly_metrics_snapshot assembly;
	resolver_cache_metrics_snapshot cache;
	listener_metrics_snapshot listener;
	resolver_supervisor_metrics_snapshot supervisor;
} listener_metrics_aggregate_snapshot;
typedef struct {
	uint64_t cycle_id;
	struct timespec degraded_logged_at;
	bool degraded_logged_at_valid;
	uint64_t suppressed;
} listener_metrics_helper_log_state;
typedef struct {
	bool event_loss_logged_at_valid;
	struct timespec event_loss_logged_at;
	uint64_t format_drops;
	listener_metrics_helper_log_state helper[RESOLVER_SUPERVISOR_HELPER_COUNT];
	uint64_t logger_errors;
	uint64_t missed_intervals;
	uint64_t observation_dropped_seen;
	pid_t process_id;
	uint64_t scheduler_failures;
	uint64_t sequence;
	struct timespec started_at;
} listener_metrics_runtime;

/* section: functions (exported) */
void listener_metrics_accept_capacity_rejected_record(listener_metrics_state *metrics);
void listener_metrics_accept_fd_exhausted_record(listener_metrics_state *metrics);
void listener_metrics_accept_record(listener_metrics_state *metrics);
void listener_metrics_connection_add(listener_metrics_state *metrics);
void listener_metrics_connection_remove(listener_metrics_state *metrics);
void listener_metrics_connection_track_failure_record(listener_metrics_state *metrics);
bool listener_metrics_effectively_enabled(const conf *config);
void listener_metrics_format_drop_record(listener_metrics_runtime *runtime);
void listener_metrics_helper_observation_log(listener_metrics_runtime *runtime, const resolver_supervisor_observation *observation, const char *log_filename, uint8_t log_level,
	const struct timespec *processed_at);
void listener_metrics_helper_observation_loss_log(listener_metrics_runtime *runtime, uint64_t observation_dropped, const char *log_filename, uint8_t log_level, const struct timespec *processed_at);
void listener_metrics_limits_set(listener_metrics_state *metrics, uint64_t connection_limit, uint64_t worker_limit);
void listener_metrics_missed_intervals_record(listener_metrics_runtime *runtime, uint64_t amount);
void listener_metrics_output(listener_metrics_runtime *runtime, listener_metrics_output_reason reason, const listener_metrics_aggregate_snapshot *snapshot,
	const char *log_filename, uint8_t log_level, const struct timespec *now);
bool listener_metrics_route_duration_enable(listener_metrics_route_request *request);
bool listener_metrics_route_pending(listener_metrics_state *metrics, listener_metrics_route_request *request);
bool listener_metrics_route_release_failure_record(listener_metrics_state *metrics, const listener_metrics_route_request *request);
bool listener_metrics_route_resolution_record(listener_metrics_state *metrics, listener_metrics_route_request *request, listener_metrics_resolution resolution);
bool listener_metrics_route_settle(listener_metrics_state *metrics, listener_metrics_route_request *request, listener_metrics_outcome outcome,
	listener_metrics_selected_family selected_family, const struct timespec *now);
bool listener_metrics_route_start(listener_metrics_state *metrics, listener_metrics_route_request *request, listener_metrics_request_mode mode, const struct timespec *now);
bool listener_metrics_runtime_init(listener_metrics_runtime *runtime, pid_t process_id, const struct timespec *started_at);
void listener_metrics_scheduler_failure_record(listener_metrics_runtime *runtime);
bool listener_metrics_snapshot_get(const listener_metrics_state *metrics, listener_metrics_snapshot *result);
void listener_metrics_worker_add(listener_metrics_state *metrics);
void listener_metrics_worker_capacity_refusal_record(listener_metrics_state *metrics);
void listener_metrics_worker_fork_failure_record(listener_metrics_state *metrics);
void listener_metrics_worker_remove(listener_metrics_state *metrics);

#endif
