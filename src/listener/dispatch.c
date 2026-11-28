/*
 * listener/dispatch.c: Dispatch listener connection events and route waiters
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* section: headers (project) */
#ifdef LISTENER_TIMER_REARM_TEST
#include "../listener_runtime_hooks.h"
#endif
#include "../log.h"
#include "../timeutil.h"
#include "admission.h"
#include "connection.h"
#include "connection_route.h"
#include "context.h"
#include "events.h"
#include "short.h"
#include "socket.h"
#include "workers.h"

/* section: headers (self) */
#include "dispatch.h"

/* section: functions (local) */
static int listener_connection_apply_progress(listener_connection *connections, listener_connection *connection, listener_connection_progress progress, listener_socket *listener,
	listener_events *events, pid_t listener_pid, listener_context *context, const struct timespec *now) {
	if (progress == LISTENER_CONNECTION_READY) {
		switch (connection->dispatch) {
			case LISTENER_CONNECTION_ROUTE_SHORT_LOCAL:
			case LISTENER_CONNECTION_ROUTE_SHORT_WAIT:
				progress = listener_short_start(connection, events, context->working_directory, &context->metrics, context->resolver, now);
				break;
			case LISTENER_CONNECTION_ROUTE_WORKER_BYPASS:
			case LISTENER_CONNECTION_ROUTE_WORKER_WAIT:
				progress = listener_workers_dispatch(connections, connection, listener, events, listener_pid, context, now);
				break;
			default:
				progress = LISTENER_CONNECTION_ABORT;
				break;
		}
	}
	if (progress == LISTENER_CONNECTION_FATAL) {
		return -1;
	}
	listener_connection_finish(connection, progress, context->log_filename, context->config->log.level);
	return 0;
}

static listener_connection_progress listener_connection_timeout(listener_connection *connection, uint32_t event_flags, uint64_t timer_generation,
	const listener_events *events, listener_context *context, const struct timespec *now) {
	if (!(event_flags & EPOLLIN) || (event_flags & (EPOLLERR | EPOLLHUP))) {
		return LISTENER_CONNECTION_ABORT;
	}
	uint64_t expiration_count;
	ssize_t read_size;
	do {
		read_size = read(connection->timer_fd, &expiration_count, sizeof(expiration_count));
	} while (read_size == -1 && errno == EINTR);
	if (read_size == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		return LISTENER_CONNECTION_PENDING;
	}
	if (read_size != (ssize_t)sizeof(expiration_count)) {
		return LISTENER_CONNECTION_ABORT;
	}
	struct timespec current_now = *now;
	if (timer_generation != connection->timer_source.generation && clock_gettime(CLOCK_MONOTONIC, &current_now) == -1) {
		return LISTENER_CONNECTION_FATAL;
	}
	/* A rearmed timer may have expired after epoll collected the stale readiness event. */
	if (timeutil_compare(&current_now, &connection->timer_deadline) < 0) {
		return LISTENER_CONNECTION_PENDING;
	}
	if (connection->timer == LISTENER_CONNECTION_TIMER_ROUTE) {
		return listener_connection_route_progress(connection, &context->metrics, context->resolver, &current_now);
	}
	if (connection->timer == LISTENER_CONNECTION_TIMER_SHORT_CONNECT) {
		return listener_short_connect_failure(connection, events, &current_now);
	}
	if (connection->timer == LISTENER_CONNECTION_TIMER_SHORT_IDLE || connection->timer == LISTENER_CONNECTION_TIMER_SHORT_LIFETIME || connection->timer == LISTENER_CONNECTION_TIMER_WORKER_REFUSAL) {
		return LISTENER_CONNECTION_CLOSED;
	}
	return listener_admission_timeout(connection, context->log_filename, context->config->log.level);
}

/* section: functions (exported) */
int listener_dispatch_batch(const listener_requests *requests, listener_connection *connections, listener_socket *listener, listener_events *events, pid_t listener_pid,
	listener_context *context, struct timespec *now) {
	/* Consume socket data before timers from the same epoll batch, then reject only a still-current deadline. */
	for (int timeout_pass = 0; timeout_pass <= 1; timeout_pass++) {
		if (timeout_pass == 1 && clock_gettime(CLOCK_MONOTONIC, now) == -1) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot sample the monotonic clock while processing connection deadlines: %s", strerror(errno));
			return -1;
		}
		for (size_t ready_index = 0; ready_index < requests->ready_count; ready_index++) {
			const listener_ready_event *ready = &requests->ready[ready_index];
			const listener_event_source *source = ready->source;
			listener_event_kind kind = source->kind;
			if ((kind == LISTENER_EVENT_TIMEOUT) != (bool)timeout_pass) {
				continue;
			}
			listener_connection *connection = source->connection;
			if (connection == NULL || connection->closing) {
				continue;
			}
			listener_connection_progress progress;
			if (kind == LISTENER_EVENT_TIMEOUT) {
				progress = listener_connection_timeout(connection, ready->flags, ready->source_generation, events, context, now);
			} else if (connection->state == LISTENER_CONNECTION_INITIAL) {
				progress = kind == LISTENER_EVENT_CLIENT ? listener_admission_receive(connection, ready->flags, context->log_filename, context->config->log.level) : LISTENER_CONNECTION_PENDING;
			} else if (connection->state == LISTENER_CONNECTION_ROUTE_WAITING) {
				progress = listener_connection_route_cancelled(connection, kind, ready->flags) ? LISTENER_CONNECTION_CLOSED : LISTENER_CONNECTION_PENDING;
			} else {
				progress = listener_short_event(connection, kind, ready->flags, ready->source_generation, events, now);
			}
			if (progress == LISTENER_CONNECTION_READY && connection->state == LISTENER_CONNECTION_INITIAL) {
				progress = listener_connection_route_start(connection, events, &context->metrics, context->resolver, now);
			}
			if (progress == LISTENER_CONNECTION_PENDING && listener_connection_route_cancelled(connection, kind, ready->flags)) {
				progress = LISTENER_CONNECTION_CLOSED;
			}
			if (listener_connection_apply_progress(connections, connection, progress, listener, events, listener_pid, context, now) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Connection state processing failed: %s", strerror(errno));
				return -1;
			}
		}
#ifdef LISTENER_TIMER_REARM_TEST
		if (timeout_pass == 0 && listener_test_connection_timer_rearm(requests) == -1) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot run the timer rearm regression hook: %s", strerror(errno));
			return -1;
		}
#endif
	}
	return 0;
}

void listener_dispatch_mark_cancelled(const listener_requests *requests) {
	for (size_t ready_index = 0; ready_index < requests->ready_count; ready_index++) {
		const listener_ready_event *ready = &requests->ready[ready_index];
		if (listener_connection_route_cancelled(ready->source->connection, ready->source->kind, ready->flags)) {
			ready->source->connection->closing = true;
		}
	}
}

int listener_dispatch_route_waiters(listener_connection *connections, listener_socket *listener, listener_events *events, pid_t listener_pid, listener_context *context, const struct timespec *now) {
	for (listener_connection *connection = connections; connection != NULL; connection = connection->next) {
		if (connection->closing || connection->state != LISTENER_CONNECTION_ROUTE_WAITING) {
			continue;
		}
		listener_connection_progress progress = listener_connection_route_progress(connection, &context->metrics, context->resolver, now);
		if (listener_connection_apply_progress(connections, connection, progress, listener, events, listener_pid, context, now) == -1) {
			return -1;
		}
	}
	return 0;
}
