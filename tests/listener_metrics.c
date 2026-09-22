/*
 * listener_metrics.c: Tests for listener-owned capacity and route metrics
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* section: headers (project) */
#include "listener_metrics.h"

/* section: defines */
/* assertion */
#define CHECK(condition, message) \
	do { \
		if (!(condition)) { \
			fprintf(stderr, "%s\n", message); \
			return false; \
		} \
	} while (0)

/* section: functions (local) */
static bool listener_metrics_test_capacity(void) {
	listener_metrics_state metrics = { 0 };
	listener_metrics_limits_set(&metrics, 100, 20);
	listener_metrics_accept_record(&metrics);
	listener_metrics_accept_record(&metrics);
	listener_metrics_accept_capacity_rejected_record(&metrics);
	listener_metrics_accept_fd_exhausted_record(&metrics);
	listener_metrics_connection_track_failure_record(&metrics);
	listener_metrics_connection_add(&metrics);
	listener_metrics_connection_add(&metrics);
	listener_metrics_connection_remove(&metrics);
	listener_metrics_worker_add(&metrics);
	listener_metrics_worker_add(&metrics);
	listener_metrics_worker_capacity_refusal_record(&metrics);
	listener_metrics_worker_fork_failure_record(&metrics);
	listener_metrics_worker_remove(&metrics);
	listener_metrics_snapshot snapshot;
	CHECK(listener_metrics_snapshot_get(&metrics, &snapshot), "capacity snapshot failed");
	CHECK(snapshot.accepted == 2 && snapshot.accept_capacity_rejected == 1 && snapshot.accept_fd_exhausted == 1,
		"accept counters were incorrect");
	CHECK(snapshot.connection_track_failure == 1 && snapshot.connections_current == 1 && snapshot.connections_high_water == 2,
		"connection counters were incorrect");
	CHECK(snapshot.worker_spawn == 2 && snapshot.worker_fork_failure == 1 && snapshot.worker_capacity_refusal == 1,
		"worker counters were incorrect");
	CHECK(snapshot.workers_current == 1 && snapshot.workers_high_water == 2, "worker gauges were incorrect");
	CHECK(snapshot.connection_limit == 100 && snapshot.worker_limit == 20 && snapshot.saturation_total == 0, "listener limits or saturation were incorrect");
	metrics.accepted = UINT64_MAX;
	listener_metrics_accept_record(&metrics);
	CHECK(metrics.accepted == UINT64_MAX && metrics.saturation_total == 1, "listener counter saturation was not recorded");
	listener_metrics_connection_remove(&metrics);
	listener_metrics_connection_remove(&metrics);
	listener_metrics_worker_remove(&metrics);
	listener_metrics_worker_remove(&metrics);
	CHECK(metrics.connections_current == 0 && metrics.workers_current == 0 && metrics.saturation_total == 3, "gauge underflow was not contained");
	return true;
}

static bool listener_metrics_test_invalid(void) {
	listener_metrics_state metrics = { 0 };
	listener_metrics_route_request request = { 0 };
	const struct timespec now = { .tv_sec = 1, .tv_nsec = 0 };
	CHECK(!listener_metrics_route_start(NULL, &request, LISTENER_METRICS_REQUEST_SHORT, &now), "NULL metrics accepted route start");
	CHECK(!listener_metrics_route_start(&metrics, NULL, LISTENER_METRICS_REQUEST_SHORT, &now), "NULL request accepted route start");
	CHECK(!listener_metrics_route_start(&metrics, &request, LISTENER_METRICS_REQUEST_COUNT, &now), "invalid mode accepted route start");
	CHECK(!listener_metrics_route_start(&metrics, &request, LISTENER_METRICS_REQUEST_SHORT, NULL), "NULL time accepted route start");
	CHECK(listener_metrics_route_start(&metrics, &request, LISTENER_METRICS_REQUEST_SHORT, &now), "valid route start failed");
	CHECK(!listener_metrics_route_start(&metrics, &request, LISTENER_METRICS_REQUEST_SHORT, &now), "duplicate route start succeeded");
	CHECK(!listener_metrics_route_resolution_record(&metrics, &request, LISTENER_METRICS_RESOLUTION_COUNT), "invalid resolution succeeded");
	CHECK(!listener_metrics_route_settle(&metrics, &request, LISTENER_METRICS_OUTCOME_COUNT, LISTENER_METRICS_SELECTED_FAMILY_NONE, &now),
		"invalid outcome succeeded");
	CHECK(!listener_metrics_route_settle(&metrics, &request, LISTENER_METRICS_OUTCOME_READY, LISTENER_METRICS_SELECTED_FAMILY_COUNT, &now),
		"invalid family succeeded");
	CHECK(metrics.route[LISTENER_METRICS_REQUEST_SHORT].requests_started == 1 && metrics.route[LISTENER_METRICS_REQUEST_SHORT].outcome[0] == 0,
		"invalid route operations changed counters");
	return true;
}

static bool listener_metrics_test_route_duration_error(void) {
	listener_metrics_state metrics = { 0 };
	listener_metrics_route_request request = { 0 };
	const struct timespec start = { .tv_sec = 5, .tv_nsec = 0 };
	const struct timespec end = { .tv_sec = 4, .tv_nsec = 0 };
	CHECK(listener_metrics_route_start(&metrics, &request, LISTENER_METRICS_REQUEST_SHORT, &start), "duration-error route start failed");
	CHECK(listener_metrics_route_duration_enable(&request), "duration-error route did not enable timing");
	CHECK(listener_metrics_route_pending(&metrics, &request), "duration-error route did not become pending");
	CHECK(listener_metrics_route_resolution_record(&metrics, &request, LISTENER_METRICS_RESOLUTION_WAITED), "duration-error resolution failed");
	errno = EDOM;
	CHECK(listener_metrics_route_settle(&metrics, &request, LISTENER_METRICS_OUTCOME_INTERNAL_ERROR, LISTENER_METRICS_SELECTED_FAMILY_NONE, &end),
		"duration-error route did not settle");
	CHECK(errno == EDOM, "duration-error settlement changed errno");
	listener_metrics_snapshot snapshot;
	CHECK(listener_metrics_snapshot_get(&metrics, &snapshot), "duration-error snapshot failed");
	CHECK(snapshot.route_duration[LISTENER_METRICS_REQUEST_SHORT].count == 0
		&& snapshot.route_duration[LISTENER_METRICS_REQUEST_SHORT].sample_errors == 1, "invalid route duration was not isolated");
	return true;
}

static bool listener_metrics_test_route_immediate(void) {
	listener_metrics_state metrics = { 0 };
	listener_metrics_route_request short_request = { 0 };
	listener_metrics_route_request worker_request = { 0 };
	const struct timespec now = { .tv_sec = 1, .tv_nsec = 0 };
	CHECK(listener_metrics_route_start(&metrics, &short_request, LISTENER_METRICS_REQUEST_SHORT, &now), "short route start failed");
	CHECK(listener_metrics_route_resolution_record(&metrics, &short_request, LISTENER_METRICS_RESOLUTION_LOCAL), "local resolution failed");
	CHECK(listener_metrics_route_settle(&metrics, &short_request, LISTENER_METRICS_OUTCOME_READY, LISTENER_METRICS_SELECTED_FAMILY_NONE, &now),
		"local route settlement failed");
	CHECK(listener_metrics_route_start(&metrics, &worker_request, LISTENER_METRICS_REQUEST_WORKER, &now), "worker route start failed");
	CHECK(listener_metrics_route_resolution_record(&metrics, &worker_request, LISTENER_METRICS_RESOLUTION_BYPASS), "bypass resolution failed");
	CHECK(listener_metrics_route_settle(&metrics, &worker_request, LISTENER_METRICS_OUTCOME_READY, LISTENER_METRICS_SELECTED_FAMILY_NONE, &now),
		"bypass route settlement failed");
	CHECK(!listener_metrics_route_settle(&metrics, &worker_request, LISTENER_METRICS_OUTCOME_INTERNAL_ERROR, LISTENER_METRICS_SELECTED_FAMILY_IPV4, &now),
		"duplicate route settlement succeeded");
	CHECK(metrics.route[LISTENER_METRICS_REQUEST_SHORT].requests_started == 1
		&& metrics.route[LISTENER_METRICS_REQUEST_SHORT].resolution[LISTENER_METRICS_RESOLUTION_LOCAL] == 1
		&& metrics.route[LISTENER_METRICS_REQUEST_SHORT].outcome[LISTENER_METRICS_OUTCOME_READY] == 1, "local route metrics were incorrect");
	CHECK(metrics.route[LISTENER_METRICS_REQUEST_WORKER].requests_started == 1
		&& metrics.route[LISTENER_METRICS_REQUEST_WORKER].resolution[LISTENER_METRICS_RESOLUTION_BYPASS] == 1
		&& metrics.route[LISTENER_METRICS_REQUEST_WORKER].outcome[LISTENER_METRICS_OUTCOME_READY] == 1, "bypass route metrics were incorrect");
	CHECK(metrics.route_duration[LISTENER_METRICS_REQUEST_SHORT].count == 0 && metrics.route_duration[LISTENER_METRICS_REQUEST_WORKER].count == 0,
		"local or bypass route produced a duration sample");
	return true;
}

static bool listener_metrics_test_route_pending(void) {
	listener_metrics_state metrics = { 0 };
	listener_metrics_route_request request = { 0 };
	const struct timespec start = { .tv_sec = 1, .tv_nsec = 0 };
	const struct timespec end = { .tv_sec = 1, .tv_nsec = 50000000 };
	CHECK(listener_metrics_route_start(&metrics, &request, LISTENER_METRICS_REQUEST_WORKER, &start), "pending route start failed");
	CHECK(listener_metrics_route_duration_enable(&request), "pending route did not enable timing");
	CHECK(listener_metrics_route_pending(&metrics, &request), "pending route did not enter pending");
	CHECK(!listener_metrics_route_pending(&metrics, &request), "pending route entered pending twice");
	CHECK(listener_metrics_route_resolution_record(&metrics, &request, LISTENER_METRICS_RESOLUTION_WAITED), "waited resolution failed");
	CHECK(!listener_metrics_route_resolution_record(&metrics, &request, LISTENER_METRICS_RESOLUTION_IMMEDIATE), "route recorded two resolutions");
	CHECK(listener_metrics_route_settle(&metrics, &request, LISTENER_METRICS_OUTCOME_READY, LISTENER_METRICS_SELECTED_FAMILY_IPV6, &end),
		"pending route settlement failed");
	CHECK(!request.pending && request.settled, "pending route latch was incorrect");
	listener_metrics_state original = metrics;
	listener_metrics_snapshot snapshot;
	CHECK(listener_metrics_snapshot_get(&metrics, &snapshot), "pending route snapshot failed");
	CHECK(memcmp(&metrics, &original, sizeof(metrics)) == 0, "listener snapshot changed its source");
	const listener_metrics_route *route = &snapshot.route[LISTENER_METRICS_REQUEST_WORKER];
	CHECK(route->requests_started == 1 && route->pending_current == 0 && route->pending_high_water == 1, "pending route gauges were incorrect");
	CHECK(route->resolution[LISTENER_METRICS_RESOLUTION_WAITED] == 1 && route->outcome[LISTENER_METRICS_OUTCOME_READY] == 1,
		"pending route resolution or outcome was incorrect");
	CHECK(route->selected_family[LISTENER_METRICS_SELECTED_FAMILY_IPV6] == 1 && route->selected_family[LISTENER_METRICS_SELECTED_FAMILY_IPV4] == 0,
		"selected family was incorrect");
	CHECK(snapshot.route_duration[LISTENER_METRICS_REQUEST_WORKER].count == 1 && snapshot.route_duration[LISTENER_METRICS_REQUEST_WORKER].sum == 50000,
		"route duration sample was incorrect");
	CHECK(route->requests_started == route->pending_current + route->outcome[LISTENER_METRICS_OUTCOME_READY], "route conservation failed");
	return true;
}

static bool listener_metrics_test_route_terminal_variants(void) {
	listener_metrics_state metrics = { 0 };
	const struct timespec start = { .tv_sec = 1, .tv_nsec = 0 };
	const struct timespec end = { .tv_sec = 2, .tv_nsec = 0 };
	listener_metrics_route_request create_failure = { 0 };
	CHECK(listener_metrics_route_start(&metrics, &create_failure, LISTENER_METRICS_REQUEST_SHORT, &start), "create-failure route start failed");
	CHECK(listener_metrics_route_settle(&metrics, &create_failure, LISTENER_METRICS_OUTCOME_LIMIT, LISTENER_METRICS_SELECTED_FAMILY_IPV4, &end),
		"create-failure route settlement failed");
	listener_metrics_route_request abandoned = { 0 };
	CHECK(listener_metrics_route_start(&metrics, &abandoned, LISTENER_METRICS_REQUEST_SHORT, &start), "abandoned route start failed");
	CHECK(listener_metrics_route_duration_enable(&abandoned) && listener_metrics_route_pending(&metrics, &abandoned), "abandoned route did not become pending");
	CHECK(listener_metrics_route_resolution_record(&metrics, &abandoned, LISTENER_METRICS_RESOLUTION_WAITED), "abandoned resolution failed");
	CHECK(listener_metrics_route_settle(&metrics, &abandoned, LISTENER_METRICS_OUTCOME_ABANDONED, LISTENER_METRICS_SELECTED_FAMILY_NONE, &end),
		"abandoned route settlement failed");
	CHECK(listener_metrics_route_release_failure_record(&metrics, &abandoned), "route release failure was not recorded");
	const listener_metrics_route *route = &metrics.route[LISTENER_METRICS_REQUEST_SHORT];
	CHECK(route->requests_started == 2 && route->outcome[LISTENER_METRICS_OUTCOME_LIMIT] == 1 && route->outcome[LISTENER_METRICS_OUTCOME_ABANDONED] == 1,
		"terminal route outcomes were incorrect");
	CHECK(route->selected_family[LISTENER_METRICS_SELECTED_FAMILY_IPV4] == 0, "failed route recorded a selected family");
	CHECK(route->release_failure == 1 && route->requests_started == route->pending_current + 2, "release failure or route conservation was incorrect");
	CHECK(metrics.route_duration[LISTENER_METRICS_REQUEST_SHORT].count == 1, "route duration eligibility was incorrect");
	return true;
}

/* section: functions (entry point) */
int main(void) {
	if (!listener_metrics_test_capacity() || !listener_metrics_test_invalid() || !listener_metrics_test_route_duration_error()
		|| !listener_metrics_test_route_immediate() || !listener_metrics_test_route_pending() || !listener_metrics_test_route_terminal_variants()) {
		return 1;
	}
	return 0;
}
