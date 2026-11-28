/*
 * listener/short.c: Listener-owned STATUS relay and buffered responses
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* section: headers (project) */
#include "../connection/setup.h"
#include "../connection/setup_short.h"
#include "../log.h"
#include "../network.h"
#include "../protocol/common.h"
#include "../protocol/handshake.h"
#include "../protocol/handshake_legacy.h"
#include "../timeutil.h"
#include "connection.h"
#include "events.h"
#include "metrics.h"

/* section: headers (self) */
#include "short.h"

/* section: defines */
#ifndef LISTENER_SHORT_CONNECT_TIMEOUT_SEC
#define LISTENER_SHORT_CONNECT_TIMEOUT_SEC	5
#endif
#ifndef LISTENER_SHORT_RELAY_BUFFER_BYTES
#define LISTENER_SHORT_RELAY_BUFFER_BYTES	8192
#endif
#ifndef LISTENER_SHORT_RELAY_IDLE_TIMEOUT_SEC
#define LISTENER_SHORT_RELAY_IDLE_TIMEOUT_SEC	10
#endif

#ifndef LISTENER_WORKER_REFUSAL_TIMEOUT_SEC
#define LISTENER_WORKER_REFUSAL_TIMEOUT_SEC	1
#endif
#if LISTENER_WORKER_REFUSAL_TIMEOUT_SEC < 1
#error "LISTENER_WORKER_REFUSAL_TIMEOUT_SEC must be positive"
#endif

/* section: functions (local) */
static bool listener_short_buffer_prepare(listener_connection *connection) {
	if (connection->short_plan.response == NULL || connection->short_plan.response_size == 0 || connection->short_plan.response_size > LISTENER_SHORT_RELAY_BUFFER_BYTES) {
		return false;
	}
	connection->upstream_buffer.data = malloc(LISTENER_SHORT_RELAY_BUFFER_BYTES);
	if (connection->upstream_buffer.data == NULL) {
		return false;
	}
	connection->upstream_buffer.capacity = LISTENER_SHORT_RELAY_BUFFER_BYTES;
	connection->upstream_buffer.size = connection->short_plan.response_size;
	connection->upstream_buffer_owned = true;
	memcpy(connection->upstream_buffer.data, connection->short_plan.response, connection->short_plan.response_size);
	free(connection->short_plan.response);
	connection->short_plan.response = NULL;
	connection->short_plan.response_size = 0;
	connection->client_buffer.capacity = sizeof(connection->inbound);
	connection->client_buffer.data = connection->inbound;
	connection->inbound_size = 0;
	return true;
}

static int listener_short_buffer_receive(listener_connection_buffer *buffer, int socket_fd, bool *read_closed, size_t *activity) {
	if (buffer == NULL || buffer->data == NULL || buffer->capacity == 0 || buffer->offset > buffer->capacity || buffer->size > buffer->capacity - buffer->offset
		|| read_closed == NULL || activity == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (buffer->offset > 0 && buffer->offset + buffer->size == buffer->capacity) {
		memmove(buffer->data, buffer->data + buffer->offset, buffer->size);
		buffer->offset = 0;
	}
	while (buffer->offset + buffer->size < buffer->capacity) {
		ssize_t receive_size = recv(socket_fd, buffer->data + buffer->offset + buffer->size, buffer->capacity - buffer->offset - buffer->size, 0);
		if (receive_size > 0) {
			buffer->size += (size_t)receive_size;
			*activity += (size_t)receive_size;
			continue;
		}
		if (receive_size == 0) {
			*read_closed = true;
			return 0;
		}
		if (errno == EINTR) {
			continue;
		}
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}
		return -1;
	}
	return 0;
}

static int listener_short_buffer_send(listener_connection_buffer *buffer, int socket_fd, size_t *activity) {
	if (buffer == NULL || buffer->data == NULL || buffer->capacity == 0 || buffer->offset > buffer->capacity || buffer->size > buffer->capacity - buffer->offset || activity == NULL) {
		errno = EINVAL;
		return -1;
	}
	while (buffer->size > 0) {
		ssize_t send_size = send(socket_fd, buffer->data + buffer->offset, buffer->size, MSG_NOSIGNAL);
		if (send_size > 0) {
			buffer->offset += (size_t)send_size;
			buffer->size -= (size_t)send_size;
			*activity += (size_t)send_size;
			if (buffer->size == 0) {
				buffer->offset = 0;
			}
			continue;
		}
		if (send_size == -1 && errno == EINTR) {
			continue;
		}
		if (send_size == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return 0;
		}
		return -1;
	}
	return 0;
}

static int listener_short_data_send(int socket_fd, const uint8_t *data, size_t size, size_t *offset, size_t *activity) {
	if (socket_fd < 0 || (data == NULL && size != 0) || offset == NULL || *offset > size || activity == NULL) {
		errno = EINVAL;
		return -1;
	}
	while (*offset < size) {
		ssize_t send_size = send(socket_fd, data + *offset, size - *offset, MSG_NOSIGNAL);
		if (send_size > 0) {
			*offset += (size_t)send_size;
			*activity += (size_t)send_size;
			continue;
		}
		if (send_size == -1 && errno == EINTR) {
			continue;
		}
		if (send_size == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return 0;
		}
		return -1;
	}
	return 0;
}

static listener_connection_progress listener_short_drive(listener_connection *connection, const listener_events *events, const struct timespec *now, size_t activity) {
	if (timeutil_compare(now, &connection->lifetime_deadline) >= 0) {
		return LISTENER_CONNECTION_CLOSED;
	}
	if (connection->state == LISTENER_CONNECTION_SHORT_RESPONDING || connection->state == LISTENER_CONNECTION_WORKER_REFUSING) {
		if (listener_short_buffer_send(&connection->upstream_buffer, connection->socket_fd, &activity) == -1) {
			return LISTENER_CONNECTION_CLOSED;
		}
		if (connection->upstream_buffer.size == 0) {
			return LISTENER_CONNECTION_CLOSED;
		}
		if (connection->state == LISTENER_CONNECTION_SHORT_RESPONDING && activity > 0
			&& listener_connection_timer_arm_short(connection, LISTENER_CONNECTION_TIMER_SHORT_IDLE, now, LISTENER_SHORT_RELAY_IDLE_TIMEOUT_SEC) == -1) {
			return LISTENER_CONNECTION_ABORT;
		}
		return listener_connection_interests_update(connection, events) == -1 ? LISTENER_CONNECTION_FATAL : LISTENER_CONNECTION_PENDING;
	}
	if (connection->state != LISTENER_CONNECTION_SHORT_RELAYING) {
		return listener_connection_interests_update(connection, events) == -1 ? LISTENER_CONNECTION_FATAL : LISTENER_CONNECTION_PENDING;
	}
	if (listener_short_data_send(connection->upstream_fd, connection->short_plan.request, connection->short_plan.request_size, &connection->request_offset, &activity) == -1) {
		return LISTENER_CONNECTION_CLOSED;
	}
	if (connection->request_offset == connection->short_plan.request_size && connection->short_plan.request_size > 0) {
		free(connection->short_plan.request);
		connection->short_plan.request = NULL;
		connection->short_plan.request_size = 0;
		connection->request_offset = 0;
	}
	if ((connection->short_plan.request_size == 0 && listener_short_buffer_send(&connection->client_buffer, connection->upstream_fd, &activity) == -1)
		|| listener_short_buffer_send(&connection->upstream_buffer, connection->socket_fd, &activity) == -1) {
		return LISTENER_CONNECTION_CLOSED;
	}
	if (connection->client_buffer.size == 0) {
		connection->client_read_paused = false;
	}
	if (connection->upstream_buffer.size == 0) {
		connection->upstream_read_paused = false;
	}
	if (connection->client_read_closed && !connection->upstream_write_closed && connection->short_plan.request_size == 0 && connection->client_buffer.size == 0) {
		if (shutdown(connection->upstream_fd, SHUT_WR) == -1) {
			return LISTENER_CONNECTION_CLOSED;
		}
		connection->upstream_write_closed = true;
	}
	if (connection->upstream_read_closed && !connection->client_write_closed && connection->upstream_buffer.size == 0) {
		if (shutdown(connection->socket_fd, SHUT_WR) == -1) {
			return LISTENER_CONNECTION_CLOSED;
		}
		connection->client_write_closed = true;
	}
	if (connection->client_read_closed && connection->upstream_read_closed && connection->short_plan.request_size == 0 && connection->client_buffer.size == 0 && connection->upstream_buffer.size == 0) {
		return LISTENER_CONNECTION_CLOSED;
	}
	if (activity > 0 && listener_connection_timer_arm_short(connection, LISTENER_CONNECTION_TIMER_SHORT_IDLE, now, LISTENER_SHORT_RELAY_IDLE_TIMEOUT_SEC) == -1) {
		return LISTENER_CONNECTION_ABORT;
	}
	return listener_connection_interests_update(connection, events) == -1 ? LISTENER_CONNECTION_FATAL : LISTENER_CONNECTION_PENDING;
}

static void listener_short_log(const listener_connection *connection, bool connected) {
	const connection_setup_short_plan *plan = &connection->short_plan;
	const route_endpoint_snapshot *endpoint = &plan->snapshot.endpoint;
	const char *destination = endpoint->target_name[0] == '\0' ? endpoint->configured_address : endpoint->target_name;
	if (plan->result == CONNECTION_SETUP_EOLDCLIENT) {
		connection_setup_log_access(&plan->snapshot, MKSYS_LEVEL_WARNING, &plan->inbound_address,
			"type: motd, status: %s",
			plan->protocol == PVER_MODERN1 ? "reject_motdrelay_13w41*" : "reject_motdrelay_oldclient"
		);
	} else if (plan->result == CONNECTION_SETUP_ENOVHOST) {
		connection_setup_log_access(&plan->snapshot, MKSYS_LEVEL_WARNING, &plan->inbound_address,
			"type: motd, vhost: %s, status: reject_vhostinvalid",
			endpoint->vhost
		);
	} else if (plan->result == CONNECTION_SETUP_ENORECORD) {
		connection_setup_log_access(&plan->snapshot, MKSYS_LEVEL_WARNING, &plan->inbound_address,
			"type: motd, vhost: %s, status: reject_dstnoresolve",
			endpoint->vhost
		);
	} else if (plan->result == CONNECTION_SETUP_OK) {
		connection_setup_log_access(&plan->snapshot, connected ? MKSYS_LEVEL_INFORMATION + 1 : MKSYS_LEVEL_WARNING, &plan->inbound_address,
			"type: motd, vhost: %s, dst: %s:%d, status: %s",
			endpoint->vhost, destination, endpoint->port, connected ? "accept" : "reject_dstnoconnect"
		);
	}
}

static listener_connection_progress listener_short_connect_complete(listener_connection *connection, const listener_events *events, const struct timespec *now) {
	net_connect_status status = net_connect_nonblocking_complete(connection->upstream_fd);
	if (status != NET_CONNECT_OK) {
		return listener_short_connect_failure(connection, events, now);
	}
	if (timeutil_compare(now, &connection->lifetime_deadline) >= 0) {
		return LISTENER_CONNECTION_CLOSED;
	}
	connection->state = LISTENER_CONNECTION_SHORT_RELAYING;
	connection->upstream_buffer.offset = 0;
	connection->upstream_buffer.size = 0;
	listener_short_log(connection, true);
	if (listener_connection_timer_arm_short(connection, LISTENER_CONNECTION_TIMER_SHORT_IDLE, now, LISTENER_SHORT_RELAY_IDLE_TIMEOUT_SEC) == -1) {
		return LISTENER_CONNECTION_ABORT;
	}
	return LISTENER_CONNECTION_PENDING;
}

static void listener_short_upstream_close(listener_connection *connection, const listener_events *events) {
	if (connection->upstream_fd == -1) {
		return;
	}
	if (connection->upstream_registered) {
		listener_events_remove(events, connection->upstream_fd);
	}
	close(connection->upstream_fd);
	connection->upstream_fd = -1;
	connection->upstream_events = 0;
	connection->upstream_registered = false;
	connection->upstream_source.generation = connection->upstream_source.generation == UINT64_MAX ? 1 : connection->upstream_source.generation + 1U;
}

/* section: functions (exported) */
listener_connection_progress listener_short_connect_failure(listener_connection *connection, const listener_events *events, const struct timespec *now) {
	if (timeutil_compare(now, &connection->lifetime_deadline) >= 0) {
		return LISTENER_CONNECTION_CLOSED;
	}
	listener_short_log(connection, false);
	listener_short_upstream_close(connection, events);
	connection->state = LISTENER_CONNECTION_SHORT_RESPONDING;
	if (listener_connection_timer_arm_short(connection, LISTENER_CONNECTION_TIMER_SHORT_IDLE, now, LISTENER_SHORT_RELAY_IDLE_TIMEOUT_SEC) == -1) {
		return LISTENER_CONNECTION_ABORT;
	}
	return listener_short_drive(connection, events, now, 0);
}

listener_connection_progress listener_short_event(listener_connection *connection, listener_event_kind kind, uint32_t event_flags,
	uint64_t source_generation, const listener_events *events, const struct timespec *now) {
	size_t activity = 0;
	if (kind == LISTENER_EVENT_CLIENT) {
		if (event_flags & EPOLLERR) {
			return LISTENER_CONNECTION_CLOSED;
		}
		if (connection->state != LISTENER_CONNECTION_SHORT_RESPONDING && connection->state != LISTENER_CONNECTION_WORKER_REFUSING
			&& (event_flags & (EPOLLIN | EPOLLHUP | EPOLLRDHUP))
			&& listener_short_buffer_receive(&connection->client_buffer, connection->socket_fd, &connection->client_read_closed, &activity) == -1) {
			return LISTENER_CONNECTION_CLOSED;
		}
		if (connection->client_buffer.size == connection->client_buffer.capacity) {
			connection->client_read_paused = true;
		}
	} else if (kind == LISTENER_EVENT_UPSTREAM) {
		if (source_generation != connection->upstream_source.generation) {
			return LISTENER_CONNECTION_PENDING;
		}
		if (connection->state == LISTENER_CONNECTION_SHORT_CONNECTING) {
			listener_connection_progress progress = listener_short_connect_complete(connection, events, now);
			if (progress != LISTENER_CONNECTION_PENDING) {
				return progress;
			}
		}
		if (connection->state == LISTENER_CONNECTION_SHORT_RELAYING) {
			if (event_flags & EPOLLERR) {
				return LISTENER_CONNECTION_CLOSED;
			}
			if ((event_flags & (EPOLLIN | EPOLLHUP | EPOLLRDHUP))
				&& listener_short_buffer_receive(&connection->upstream_buffer, connection->upstream_fd, &connection->upstream_read_closed, &activity) == -1) {
				return LISTENER_CONNECTION_CLOSED;
			}
			if (connection->upstream_buffer.size == connection->upstream_buffer.capacity) {
				connection->upstream_read_paused = true;
			}
		}
	} else {
		errno = EINVAL;
		return LISTENER_CONNECTION_FATAL;
	}
	return listener_short_drive(connection, events, now, activity);
}

listener_connection_progress listener_short_refuse(listener_connection *connection, const listener_events *events, listener_metrics_state *metrics,
	resolver_supervisor *supervisor, const struct timespec *now) {
	static const char notice[] = "[Proxy] Proxy is full, try again later.";
	size_t packet_size;
	switch (protocol_identify(connection->inbound, connection->inbound_size, NULL)) {
		case PVER_LEGACYL1:
		case PVER_LEGACYL2:
		case PVER_LEGACYL3:
		case PVER_LEGACYL4:
			packet_size = make_kickreason_legacy(connection->inbound, sizeof(connection->inbound), notice);
			break;
		case PVER_MODERN1:
		case PVER_MODERN2:
			packet_size = make_kickreason(connection->inbound, sizeof(connection->inbound), notice);
			break;
		case PVER_ORIGPRO:
		case PVER_UNIDENT:
		default:
			return LISTENER_CONNECTION_CLOSED;
	}
	if (packet_size == 0) {
		return LISTENER_CONNECTION_ABORT;
	}
	if (!listener_connection_route_release(connection, metrics, supervisor, now)) {
		return LISTENER_CONNECTION_FATAL;
	}
	connection->inbound_size = 0;
	connection->state = LISTENER_CONNECTION_WORKER_REFUSING;
	connection->upstream_buffer.capacity = sizeof(connection->inbound);
	connection->upstream_buffer.data = connection->inbound;
	connection->upstream_buffer.offset = 0;
	connection->upstream_buffer.size = packet_size;
	connection->upstream_buffer_owned = false;
	if (listener_connection_timer_arm_short(connection, LISTENER_CONNECTION_TIMER_WORKER_REFUSAL, now, LISTENER_WORKER_REFUSAL_TIMEOUT_SEC) == -1) {
		return LISTENER_CONNECTION_ABORT;
	}
	return listener_short_drive(connection, events, now, 0);
}

listener_connection_progress listener_short_start(listener_connection *connection, const listener_events *events, const char *working_directory, listener_metrics_state *metrics,
	resolver_supervisor *supervisor, const struct timespec *now) {
	connection_setup_snapshot snapshot;
	if (!listener_connection_snapshot_prepare(connection, working_directory, &snapshot)) {
		return LISTENER_CONNECTION_ABORT;
	}
	net_addrbundle client = listener_connection_client(connection);
	connection_setup_short_action action = connection_setup_short_prepare(&connection->short_plan, &snapshot, client, connection->inbound, connection->inbound_size);
	if (!listener_connection_route_release(connection, metrics, supervisor, now)) {
		return LISTENER_CONNECTION_FATAL;
	}
	if (action == CONNECTION_SETUP_SHORT_ABORT || !listener_short_buffer_prepare(connection)) {
		return LISTENER_CONNECTION_ABORT;
	}
	if (action == CONNECTION_SETUP_SHORT_RESPOND) {
		listener_short_log(connection, false);
		connection->state = LISTENER_CONNECTION_SHORT_RESPONDING;
		if (listener_connection_timer_arm_short(connection, LISTENER_CONNECTION_TIMER_SHORT_IDLE, now, LISTENER_SHORT_RELAY_IDLE_TIMEOUT_SEC) == -1) {
			return LISTENER_CONNECTION_ABORT;
		}
		return listener_short_drive(connection, events, now, 0);
	}
	net_connect_status connect_status = net_connect_nonblocking(&connection->short_plan.snapshot.endpoint.address, connection->short_plan.snapshot.endpoint.port, &connection->upstream_fd);
	if (connect_status != NET_CONNECT_OK && connect_status != NET_CONNECT_PENDING) {
		return listener_short_connect_failure(connection, events, now);
	}
	connection->upstream_source.generation = connection->upstream_source.generation == UINT64_MAX ? 1 : connection->upstream_source.generation + 1U;
	if (connect_status == NET_CONNECT_PENDING) {
		connection->state = LISTENER_CONNECTION_SHORT_CONNECTING;
		if (listener_connection_timer_arm_short(connection, LISTENER_CONNECTION_TIMER_SHORT_CONNECT, now, LISTENER_SHORT_CONNECT_TIMEOUT_SEC) == -1) {
			return LISTENER_CONNECTION_ABORT;
		}
	} else {
		connection->state = LISTENER_CONNECTION_SHORT_RELAYING;
		connection->upstream_buffer.size = 0;
		listener_short_log(connection, true);
		if (listener_connection_timer_arm_short(connection, LISTENER_CONNECTION_TIMER_SHORT_IDLE, now, LISTENER_SHORT_RELAY_IDLE_TIMEOUT_SEC) == -1) {
			return LISTENER_CONNECTION_ABORT;
		}
	}
	return listener_short_drive(connection, events, now, 0);
}
