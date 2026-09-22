/*
 * listener_metrics.c: Listener-owned capacity and route metrics
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Bilin Tsui
 */

/* section: headers (library) */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/* section: headers (project) */
#include "metrics.h"

/* section: headers (self) */
#include "listener_metrics.h"

/* section: functions (local) */
static void listener_metrics_decrement(listener_metrics_state *metrics, uint64_t *gauge) {
	if (*gauge > 0) {
		(*gauge)--;
	} else {
		(void)metrics_counter_add(&metrics->saturation_total, 1, &metrics->saturation_total);
	}
}

static void listener_metrics_increment(listener_metrics_state *metrics, uint64_t *counter) {
	(void)metrics_counter_add(counter, 1, &metrics->saturation_total);
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

void listener_metrics_limits_set(listener_metrics_state *metrics, uint64_t connection_limit, uint64_t worker_limit) {
	if (metrics == NULL) {
		return;
	}
	metrics->connection_limit = connection_limit;
	metrics->worker_limit = worker_limit;
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

bool listener_metrics_route_start(listener_metrics_state *metrics, listener_metrics_route_request *request, listener_metrics_request_mode mode,
	const struct timespec *now) {
	if (metrics == NULL || request == NULL || request->started || mode >= LISTENER_METRICS_REQUEST_COUNT || now == NULL) {
		return false;
	}
	request->mode = mode;
	request->started = true;
	request->started_at = *now;
	listener_metrics_increment(metrics, &metrics->route[mode].requests_started);
	return true;
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
