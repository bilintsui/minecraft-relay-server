/*
 * listener/connection_route.c: Route selection and resolution for a listener-owned connection
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>

/* section: headers (project) */
#include "../network.h"
#include "../protocol/common.h"
#include "../protocol/handshake.h"
#include "../protocol/handshake_legacy.h"
#include "../protocol/proxy.h"
#include "../route/waiter.h"
#include "connection.h"
#include "events.h"
#include "metrics.h"

/* section: headers (self) */
#include "connection_route.h"

/* section: functions (local) */
static listener_metrics_selected_family listener_connection_route_metrics_family(const listener_connection *connection) {
	if (connection->endpoint.address.family == AF_INET) {
		return LISTENER_METRICS_SELECTED_FAMILY_IPV4;
	}
	if (connection->endpoint.address.family == AF_INET6) {
		return LISTENER_METRICS_SELECTED_FAMILY_IPV6;
	}
	return LISTENER_METRICS_SELECTED_FAMILY_NONE;
}

static listener_metrics_request_mode listener_connection_route_metrics_mode(listener_connection_route route) {
	if (route == LISTENER_CONNECTION_ROUTE_SHORT_LOCAL || route == LISTENER_CONNECTION_ROUTE_SHORT_WAIT) {
		return LISTENER_METRICS_REQUEST_SHORT;
	}
	if (route == LISTENER_CONNECTION_ROUTE_WORKER_BYPASS || route == LISTENER_CONNECTION_ROUTE_WORKER_WAIT) {
		return LISTENER_METRICS_REQUEST_WORKER;
	}
	return LISTENER_METRICS_REQUEST_COUNT;
}

static listener_metrics_outcome listener_connection_route_metrics_outcome(route_waiter_status status) {
	switch (status) {
		case ROUTE_WAITER_READY:
			return LISTENER_METRICS_OUTCOME_READY;
		case ROUTE_WAITER_CONTRADICTORY:
			return LISTENER_METRICS_OUTCOME_CONTRADICTORY;
		case ROUTE_WAITER_LIMIT:
			return LISTENER_METRICS_OUTCOME_LIMIT;
		case ROUTE_WAITER_MEMORY:
			return LISTENER_METRICS_OUTCOME_MEMORY;
		case ROUTE_WAITER_NO_ROUTE:
			return LISTENER_METRICS_OUTCOME_NO_ROUTE;
		case ROUTE_WAITER_SERVICE_UNAVAILABLE:
			return LISTENER_METRICS_OUTCOME_SERVICE_UNAVAILABLE;
		case ROUTE_WAITER_TIMEOUT:
			return LISTENER_METRICS_OUTCOME_TIMEOUT;
		case ROUTE_WAITER_UNAVAILABLE:
			return LISTENER_METRICS_OUTCOME_UNAVAILABLE;
		case ROUTE_WAITER_PENDING:
		case ROUTE_WAITER_BAD_ARGUMENT:
		case ROUTE_WAITER_IO:
		case ROUTE_WAITER_TIME:
		default:
			return LISTENER_METRICS_OUTCOME_INTERNAL_ERROR;
	}
}

static listener_connection_route listener_connection_route_parse(listener_connection *connection) {
	intent_t intent;
	protocol_version protocol = protocol_identify(connection->inbound, connection->inbound_size, &intent);
	const char *source = NULL;
	listener_connection_route route = LISTENER_CONNECTION_ROUTE_INVALID;
	p_handshake modern;
	p_login_legacy legacy_login;
	p_motd_legacy legacy_motd;
	memset(&modern, 0, sizeof(modern));
	memset(&legacy_login, 0, sizeof(legacy_login));
	memset(&legacy_motd, 0, sizeof(legacy_motd));
	switch (protocol) {
		case PVER_LEGACYL2:
		case PVER_LEGACYL4:
			legacy_login = packet_read_legacy_login(connection->inbound, connection->inbound_size, protocol);
			source = legacy_login.address;
			route = LISTENER_CONNECTION_ROUTE_WORKER_WAIT;
			break;
		case PVER_LEGACYM3:
			legacy_motd = packet_read_legacy_motd(connection->inbound, connection->inbound_size);
			source = legacy_motd.address;
			route = LISTENER_CONNECTION_ROUTE_SHORT_WAIT;
			break;
		case PVER_MODERN2:
			modern = packet_read((void *)connection->inbound, (void *)(connection->inbound + connection->inbound_size));
			if (modern.version == 0 || (modern.nextstate != CLIENT_INTENT_STATUS && modern.nextstate != CLIENT_INTENT_LOGIN && modern.nextstate != CLIENT_INTENT_TRANSFER)) {
				packet_destroy(modern);
				return LISTENER_CONNECTION_ROUTE_INVALID;
			}
			source = modern.address;
			route = modern.nextstate == CLIENT_INTENT_STATUS ? LISTENER_CONNECTION_ROUTE_SHORT_WAIT : LISTENER_CONNECTION_ROUTE_WORKER_WAIT;
			break;
		case PVER_ORIGPRO:
		case PVER_LEGACYL1:
		case PVER_LEGACYL3:
			return LISTENER_CONNECTION_ROUTE_WORKER_BYPASS;
		case PVER_LEGACYM1:
		case PVER_LEGACYM2:
			return LISTENER_CONNECTION_ROUTE_SHORT_LOCAL;
		case PVER_MODERN1:
			return intent == CLIENT_INTENT_STATUS ? LISTENER_CONNECTION_ROUTE_SHORT_LOCAL : LISTENER_CONNECTION_ROUTE_WORKER_BYPASS;
		case PVER_UNIDENT:
		default:
			return LISTENER_CONNECTION_ROUTE_INVALID;
	}
	bool valid = source != NULL && source[0] != '\0' && strlen(source) < sizeof(connection->vhost);
	if (valid) {
		memcpy(connection->vhost, source, strlen(source) + 1U);
	}
	packet_destroy(modern);
	packet_destroy_legacy_motd(legacy_motd);
	return valid ? route : LISTENER_CONNECTION_ROUTE_INVALID;
}

static void listener_connection_route_record_error(listener_connection *connection, listener_metrics_state *metrics, const struct timespec *now) {
	(void)listener_metrics_route_settle(metrics, &connection->route_metrics, LISTENER_METRICS_OUTCOME_INTERNAL_ERROR, LISTENER_METRICS_SELECTED_FAMILY_NONE, now);
}

/* section: functions (exported) */
bool listener_connection_route_cancelled(const listener_connection *connection, listener_event_kind kind, uint32_t event_flags) {
	return connection != NULL && connection->state == LISTENER_CONNECTION_ROUTE_WAITING && kind == LISTENER_EVENT_CLIENT && (event_flags & (EPOLLERR | EPOLLHUP | EPOLLRDHUP));
}

listener_connection_progress listener_connection_route_progress(listener_connection *connection, listener_metrics_state *metrics, resolver_supervisor *supervisor, const struct timespec *now) {
	connection->waiter_status = route_waiter_progress(connection->waiter, supervisor, now);
	if (connection->waiter_status == ROUTE_WAITER_PENDING) {
		(void)listener_metrics_route_pending(metrics, &connection->route_metrics);
		return LISTENER_CONNECTION_PENDING;
	}
	listener_metrics_resolution resolution = connection->route_metrics.pending ? LISTENER_METRICS_RESOLUTION_WAITED : LISTENER_METRICS_RESOLUTION_IMMEDIATE;
	(void)listener_metrics_route_resolution_record(metrics, &connection->route_metrics, resolution);
	switch (connection->waiter_status) {
		case ROUTE_WAITER_READY:
			if (!route_waiter_snapshot_take(connection->waiter, &connection->endpoint)) {
				listener_connection_route_record_error(connection, metrics, now);
				return LISTENER_CONNECTION_FATAL;
			}
			(void)listener_metrics_route_settle(metrics, &connection->route_metrics, LISTENER_METRICS_OUTCOME_READY,
				listener_connection_route_metrics_family(connection), now
			);
			return LISTENER_CONNECTION_READY;
		case ROUTE_WAITER_BAD_ARGUMENT:
			listener_connection_route_record_error(connection, metrics, now);
			errno = EINVAL;
			return LISTENER_CONNECTION_FATAL;
		case ROUTE_WAITER_IO:
			listener_connection_route_record_error(connection, metrics, now);
			errno = EIO;
			return LISTENER_CONNECTION_FATAL;
		case ROUTE_WAITER_TIME:
			listener_connection_route_record_error(connection, metrics, now);
			errno = EOVERFLOW;
			return LISTENER_CONNECTION_FATAL;
		case ROUTE_WAITER_CONTRADICTORY:
		case ROUTE_WAITER_LIMIT:
		case ROUTE_WAITER_MEMORY:
		case ROUTE_WAITER_NO_ROUTE:
		case ROUTE_WAITER_SERVICE_UNAVAILABLE:
		case ROUTE_WAITER_TIMEOUT:
		case ROUTE_WAITER_UNAVAILABLE:
		default:
			(void)listener_metrics_route_settle(metrics, &connection->route_metrics, listener_connection_route_metrics_outcome(connection->waiter_status),
				LISTENER_METRICS_SELECTED_FAMILY_NONE, now
			);
			return LISTENER_CONNECTION_READY;
	}
}

listener_connection_progress listener_connection_route_start(listener_connection *connection, const listener_events *events, listener_metrics_state *metrics,
	resolver_supervisor *supervisor, const struct timespec *now) {
	listener_connection_route route = listener_connection_route_parse(connection);
	connection->dispatch = route;
	listener_metrics_request_mode mode = listener_connection_route_metrics_mode(route);
	if (mode == LISTENER_METRICS_REQUEST_COUNT) {
		return LISTENER_CONNECTION_ABORT;
	}
	(void)listener_metrics_route_start(metrics, &connection->route_metrics, mode, now);
	if (route == LISTENER_CONNECTION_ROUTE_SHORT_LOCAL || route == LISTENER_CONNECTION_ROUTE_WORKER_BYPASS) {
		(void)listener_metrics_route_resolution_record(metrics, &connection->route_metrics,
			route == LISTENER_CONNECTION_ROUTE_SHORT_LOCAL ? LISTENER_METRICS_RESOLUTION_LOCAL : LISTENER_METRICS_RESOLUTION_BYPASS
		);
		(void)listener_metrics_route_settle(metrics, &connection->route_metrics,
			LISTENER_METRICS_OUTCOME_READY, LISTENER_METRICS_SELECTED_FAMILY_NONE, now
		);
		return LISTENER_CONNECTION_READY;
	}
	if (connection->inbound_proxy.family == AF_UNSPEC && !protocol_proxy_socket_read(connection->socket_fd, &connection->inbound_proxy)) {
		(void)listener_metrics_route_settle(metrics, &connection->route_metrics,
			LISTENER_METRICS_OUTCOME_INTERNAL_ERROR, LISTENER_METRICS_SELECTED_FAMILY_NONE, now
		);
		return LISTENER_CONNECTION_ABORT;
	}
	connection->state = LISTENER_CONNECTION_ROUTE_WAITING;
	route_waiter_create_status create_status = route_waiter_create(connection->generation, connection->vhost, &connection->inbound_proxy, now, &connection->waiter);
	if (create_status != ROUTE_WAITER_CREATE_OK) {
		if (create_status == ROUTE_WAITER_CREATE_BAD_ARGUMENT || create_status == ROUTE_WAITER_CREATE_TIME) {
			(void)listener_metrics_route_settle(metrics, &connection->route_metrics,
				LISTENER_METRICS_OUTCOME_INTERNAL_ERROR, LISTENER_METRICS_SELECTED_FAMILY_NONE, now
			);
			errno = create_status == ROUTE_WAITER_CREATE_TIME ? EOVERFLOW : EINVAL;
			return LISTENER_CONNECTION_FATAL;
		}
		connection->waiter_status = create_status == ROUTE_WAITER_CREATE_LIMIT ? ROUTE_WAITER_LIMIT : ROUTE_WAITER_MEMORY;
		(void)listener_metrics_route_settle(metrics, &connection->route_metrics,
			create_status == ROUTE_WAITER_CREATE_LIMIT ? LISTENER_METRICS_OUTCOME_LIMIT : LISTENER_METRICS_OUTCOME_MEMORY, LISTENER_METRICS_SELECTED_FAMILY_NONE, now
		);
		return LISTENER_CONNECTION_READY;
	}
	(void)listener_metrics_route_duration_enable(&connection->route_metrics);
	listener_connection_progress progress = listener_connection_route_progress(connection, metrics, supervisor, now);
	if (progress != LISTENER_CONNECTION_PENDING) {
		return progress;
	}
	struct timespec deadline;
	if (!route_waiter_deadline(connection->waiter, &deadline) || listener_connection_timer_set(connection, LISTENER_CONNECTION_TIMER_ROUTE, &deadline) == -1
		|| listener_connection_interests_update(connection, events) == -1) {
		(void)listener_metrics_route_resolution_record(metrics, &connection->route_metrics,
			LISTENER_METRICS_RESOLUTION_WAITED
		);
		(void)listener_metrics_route_settle(metrics, &connection->route_metrics,
			LISTENER_METRICS_OUTCOME_INTERNAL_ERROR, LISTENER_METRICS_SELECTED_FAMILY_NONE, now
		);
		return LISTENER_CONNECTION_FATAL;
	}
	return LISTENER_CONNECTION_PENDING;
}
