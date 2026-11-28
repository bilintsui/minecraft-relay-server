/*
 * listener/workers.c: Listener worker admission, fork handoff and reaping
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* section: headers (project) */
#include "../connection/setup_long.h"
#include "../define/exitcode.h"
#include "../log.h"
#include "../network.h"
#include "../process.h"
#include "../resolver/cache.h"
#include "../resolver/supervisor.h"
#include "../timeutil.h"
#include "connection.h"
#include "context.h"
#include "events.h"
#include "generation.h"
#include "metrics.h"
#include "short.h"
#include "socket.h"

/* section: headers (self) */
#include "workers.h"

/* section: defines */
#ifndef LISTENER_WORKER_LOG_INTERVAL_SEC
#define LISTENER_WORKER_LOG_INTERVAL_SEC	10
#endif

#define LISTENER_WORKER_PROCESS_NAME	"worker"

/* section: types */
typedef enum {
	LISTENER_WORKER_PARENT_READY,
	LISTENER_WORKER_PARENT_EXITED,
	LISTENER_WORKER_PARENT_ERROR
} listener_worker_parent_status;

/* section: functions (local) */
static listener_worker_parent_status listener_worker_parent_attach(pid_t listener_pid, const sigset_t *signal_mask, const connection_setup_snapshot *snapshot) {
	if (prctl(PR_SET_PDEATHSIG, SIGTERM) == -1) {
		CONNECTION_SETUP_LOG(snapshot, MKSYS_LEVEL_WARNING, "Cannot configure worker parent-death signal: %s", strerror(errno));
		return LISTENER_WORKER_PARENT_ERROR;
	}
	if (getppid() != listener_pid) {
		return LISTENER_WORKER_PARENT_EXITED;
	}
	if (process_child_signals_restore(signal_mask) == -1) {
		CONNECTION_SETUP_LOG(snapshot, MKSYS_LEVEL_WARNING, "Cannot restore worker signal state: %s", strerror(errno));
		return LISTENER_WORKER_PARENT_ERROR;
	}
	return LISTENER_WORKER_PARENT_READY;
}

static void listener_worker_refusal_log(listener_context *context) {
	listener_workers *workers = &context->workers;
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
		return;
	}
	struct timespec next_log;
	if (workers->refusal_logged && timeutil_add_seconds(&workers->refusal_logged_at, LISTENER_WORKER_LOG_INTERVAL_SEC, &next_log) && timeutil_compare(&now, &next_log) < 0) {
		return;
	}
	LISTENER_LOG(context, MKSYS_LEVEL_WARNING, "Worker process limit reached; refusing a new LOGIN or TRANSFER connection until a worker exits.");
	workers->refusal_logged = true;
	workers->refusal_logged_at = now;
}

static exit_code listener_worker_run(int client_fd, net_addrbundle client, const uint8_t *inbound, size_t inbound_size,
	const connection_setup_snapshot *snapshot, listener_socket *listener, listener_events *events, pid_t listener_pid, listener_context *context) {
	if (prctl(PR_SET_NAME, LISTENER_WORKER_PROCESS_NAME) == -1) {
		CONNECTION_SETUP_LOG(snapshot, MKSYS_LEVEL_WARNING, "Cannot set worker process name: %s", strerror(errno));
	}
	listener_events_dispose_in_child(events);
	listener_socket_close(listener);
	resolver_supervisor_dispose_in_child(context->resolver);
	context->resolver = NULL;
	listener_worker_parent_status parent = listener_worker_parent_attach(listener_pid, &events->previous_signal_mask, snapshot);
	listener_generation_dispose_in_child(context);
	resolver_cache_destroy(context->dns_cache);
	context->dns_cache = NULL;
	if (parent != LISTENER_WORKER_PARENT_READY) {
		return parent == LISTENER_WORKER_PARENT_EXITED ? EXITCODE_OK : EXITCODE_INTERNAL;
	}
	uint8_t seed[CONNECTION_SETUP_LONG_PENDING_MAX];
	size_t seed_size;
	int socket_outbound;
	connection_setup_status setup_status = connection_setup_long_prepared(client_fd, &socket_outbound, snapshot, client, inbound, inbound_size, seed, &seed_size);
	if (setup_status == CONNECTION_SETUP_OK) {
		net_relay(client_fd, socket_outbound, seed, seed_size);
	}
	return EXITCODE_OK;
}

/* section: functions (exported) */
listener_connection_progress listener_workers_dispatch(listener_connection *connections, listener_connection *connection, listener_socket *listener, listener_events *events,
	pid_t listener_pid, listener_context *context, const struct timespec *now) {
	if (context->workers.count >= LISTENER_WORKER_LIMIT) {
		listener_metrics_worker_capacity_refusal_record(&context->metrics);
		listener_worker_refusal_log(context);
		return listener_short_refuse(connection, events, &context->metrics, context->resolver, now);
	}
	connection_setup_snapshot snapshot;
	if (!listener_connection_snapshot_prepare(connection, context->working_directory, &snapshot)) {
		LISTENER_LOG(context, MKSYS_LEVEL_WARNING, "Cannot prepare a self-contained worker handoff.");
		connection->closing = true;
		return LISTENER_CONNECTION_PENDING;
	}
	if (!listener_connection_route_release(connection, &context->metrics, context->resolver, now)) {
		return LISTENER_CONNECTION_FATAL;
	}
	pid_t worker_pid = fork();
	if (worker_pid > 0) {
		context->workers.pids[context->workers.count] = worker_pid;
		context->workers.count++;
		listener_metrics_worker_add(&context->metrics);
		connection->closing = true;
		return LISTENER_CONNECTION_PENDING;
	}
	if (worker_pid < 0) {
		int saved_errno = errno;
		listener_metrics_worker_fork_failure_record(&context->metrics);
		connection->closing = true;
		LISTENER_LOG(context, MKSYS_LEVEL_WARNING, "Cannot create worker process: %s", strerror(saved_errno));
		listener_backoff();
		return LISTENER_CONNECTION_PENDING;
	}
	listener_connections_close_except(connections, connection);
	net_addrbundle client = listener_connection_client(connection);
	_exit(listener_worker_run(connection->socket_fd, client, connection->inbound, connection->inbound_size, &snapshot, listener, events, listener_pid, context));
}

int listener_workers_reap(listener_context *context) {
	listener_workers *workers = &context->workers;
	for (size_t index = 0; index < workers->count;) {
		pid_t result;
		do {
			result = waitpid(workers->pids[index], NULL, WNOHANG);
		} while (result == -1 && errno == EINTR);
		if (result == workers->pids[index] || (result == -1 && errno == ECHILD)) {
			workers->count--;
			workers->pids[index] = workers->pids[workers->count];
			listener_metrics_worker_remove(&context->metrics);
			continue;
		}
		if (result == -1) {
			return -1;
		}
		index++;
	}
	return 0;
}
