/*
 * listener.c: Listener and worker process runtime
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#ifdef LISTENER_TIMER_REARM_TEST
#include <poll.h>
#endif
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <systemd/sd-daemon.h>
#include <time.h>
#include <unistd.h>

/* section: headers (project) */
#include "basic.h"
#include "config.h"
#include "connection/setup_long.h"
#include "connection/setup_short.h"
#include "define/exitcode.h"
#include "log.h"
#include "network.h"
#include "protocol/common.h"
#include "protocol/handshake.h"
#include "protocol/handshake_legacy.h"
#include "protocol/proxy.h"
#include "resolver/cache.h"
#include "resolver/hosts.h"
#include "resolver/supervisor.h"
#include "route/bindings.h"
#include "route/generation.h"
#include "route/generation_registry.h"
#include "route/resolution.h"
#include "route/table.h"
#include "route/waiter.h"
#include "timeutil.h"

/* section: headers (self) */
#include "listener.h"

/* section: defines */
/* listener */
#ifndef LISTENER_ACCEPT_BATCH
#define LISTENER_ACCEPT_BATCH	128
#endif
#ifndef LISTENER_CONNECTION_FD_COUNT
#define LISTENER_CONNECTION_FD_COUNT	3
#endif
#ifndef LISTENER_CONNECTION_FD_RESERVE
#define LISTENER_CONNECTION_FD_RESERVE	16
#endif
#ifndef LISTENER_CONNECTION_LIMIT
#define LISTENER_CONNECTION_LIMIT	4096
#endif
#ifndef LISTENER_CONNECTION_LIMIT_FALLBACK
#define LISTENER_CONNECTION_LIMIT_FALLBACK	256
#endif
#ifndef LISTENER_EVENT_BATCH
#define LISTENER_EVENT_BATCH	128
#endif
#ifndef LISTENER_HOSTS_FILENAME
#define LISTENER_HOSTS_FILENAME	"/etc/hosts"
#endif
#ifndef LISTENER_ROUTE_PREWARM_BATCH_LIMIT
#define LISTENER_ROUTE_PREWARM_BATCH_LIMIT	64
#endif
#ifndef LISTENER_ROUTE_WARMUP_TIMEOUT_SEC
#define LISTENER_ROUTE_WARMUP_TIMEOUT_SEC	10
#endif
#ifndef LISTENER_WORKER_LIMIT
#define LISTENER_WORKER_LIMIT	256
#endif
#ifndef LISTENER_WORKER_LOG_INTERVAL_SEC
#define LISTENER_WORKER_LOG_INTERVAL_SEC	10
#endif
#ifndef LISTENER_WORKER_REFUSAL_TIMEOUT_SEC
#define LISTENER_WORKER_REFUSAL_TIMEOUT_SEC	1
#endif
#if LISTENER_WORKER_LIMIT < 1
#error "LISTENER_WORKER_LIMIT must be positive"
#endif
#if LISTENER_WORKER_REFUSAL_TIMEOUT_SEC < 1
#error "LISTENER_WORKER_REFUSAL_TIMEOUT_SEC must be positive"
#endif

/* initial packet */
#ifndef LISTENER_INITIAL_TIMEOUT_SEC
#define LISTENER_INITIAL_TIMEOUT_SEC	10
#endif
#ifndef LISTENER_LEGACY_PING_GRACE_MS
#define LISTENER_LEGACY_PING_GRACE_MS	100
#endif

/* process names */
#define LISTENER_PROCESS_NAME	"mrs-listener"
#define LISTENER_WORKER_PROCESS_NAME	"worker"

/* short connection */
#ifndef LISTENER_SHORT_CONNECT_TIMEOUT_SEC
#define LISTENER_SHORT_CONNECT_TIMEOUT_SEC	5
#endif
#ifndef LISTENER_SHORT_LIFETIME_TIMEOUT_SEC
#define LISTENER_SHORT_LIFETIME_TIMEOUT_SEC	30
#endif
#ifndef LISTENER_SHORT_RELAY_BUFFER_BYTES
#define LISTENER_SHORT_RELAY_BUFFER_BYTES	8192
#endif
#ifndef LISTENER_SHORT_RELAY_IDLE_TIMEOUT_SEC
#define LISTENER_SHORT_RELAY_IDLE_TIMEOUT_SEC	10
#endif

/* logging macro */
#define LISTENER_LOG(ctx, lvl, ...)	MKSYS_LOG((ctx)->log_filename, (ctx)->config->log.level, lvl, __VA_ARGS__)
#define LISTENER_LOG_TERMINAL(ctx, lvl, ...)	MKSYS_LOG(MKSYS_NOLOGFILE, (ctx)->config->log.level, lvl, __VA_ARGS__)

/* section: types */
typedef enum {
	LISTENER_ENDPOINT_OK,
	LISTENER_ENDPOINT_BAD_ADDRESS,
	LISTENER_ENDPOINT_BAD_PORT
} listener_endpoint_status;
typedef enum {
	LISTENER_CONNECTION_ABORT,
	LISTENER_CONNECTION_CLOSED,
	LISTENER_CONNECTION_FATAL,
	LISTENER_CONNECTION_PENDING,
	LISTENER_CONNECTION_READY
} listener_connection_progress;
typedef enum {
	LISTENER_CONNECTION_ROUTE_INVALID,
	LISTENER_CONNECTION_ROUTE_SHORT_LOCAL,
	LISTENER_CONNECTION_ROUTE_SHORT_WAIT,
	LISTENER_CONNECTION_ROUTE_WORKER_BYPASS,
	LISTENER_CONNECTION_ROUTE_WORKER_WAIT
} listener_connection_route;
typedef enum {
	LISTENER_CONNECTION_INITIAL,
	LISTENER_CONNECTION_ROUTE_WAITING,
	LISTENER_CONNECTION_SHORT_CONNECTING,
	LISTENER_CONNECTION_SHORT_RELAYING,
	LISTENER_CONNECTION_SHORT_RESPONDING,
	LISTENER_CONNECTION_WORKER_REFUSING
} listener_connection_state;
typedef enum {
	LISTENER_CONNECTION_TIMER_ASSEMBLY,
	LISTENER_CONNECTION_TIMER_GRACE,
	LISTENER_CONNECTION_TIMER_ROUTE,
	LISTENER_CONNECTION_TIMER_SHORT_CONNECT,
	LISTENER_CONNECTION_TIMER_SHORT_IDLE,
	LISTENER_CONNECTION_TIMER_SHORT_LIFETIME,
	LISTENER_CONNECTION_TIMER_WORKER_REFUSAL
} listener_connection_timer;
typedef enum {
	LISTENER_EVENT_CLIENT,
	LISTENER_EVENT_LISTENER,
	LISTENER_EVENT_RESOLVER,
	LISTENER_EVENT_ROUTE_TIMER,
	LISTENER_EVENT_SIGNAL,
	LISTENER_EVENT_TIMEOUT,
	LISTENER_EVENT_UPSTREAM
} listener_event_kind;
typedef enum {
	LISTENER_ROUTE_PREPARE_OK,
	LISTENER_ROUTE_PREPARE_CANDIDATE_ERROR,
	LISTENER_ROUTE_PREPARE_TIME_ERROR
} listener_route_prepare_status;
typedef enum {
	LISTENER_SOCKET_OPEN_OK,
	LISTENER_SOCKET_OPEN_BIND_ERROR,
	LISTENER_SOCKET_OPEN_EVENTS_ERROR
} listener_socket_open_status;
typedef enum {
	LISTENER_SOCKET_REPLACE_OK,
	LISTENER_SOCKET_REPLACE_CANDIDATE_ERROR,
	LISTENER_SOCKET_REPLACE_ACTIVE_ERROR,
	LISTENER_SOCKET_REPLACE_ROLLBACK_ERROR
} listener_socket_replace_status;
typedef union {
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
} listener_client_address;
typedef struct listener_connection listener_connection;
typedef struct {
	size_t capacity;
	uint8_t *data;
	size_t offset;
	size_t size;
} listener_connection_buffer;
typedef struct {
	listener_connection *connection;
	uint64_t generation;
	listener_event_kind kind;
} listener_event_source;
struct listener_connection {
	listener_client_address address;
	struct timespec assembly_deadline;
	listener_connection_buffer client_buffer;
	uint32_t client_events;
	bool client_read_closed;
	bool client_read_paused;
	listener_event_source client_source;
	bool client_registered;
	bool client_write_closed;
	bool closing;
	listener_connection_route dispatch;
	route_endpoint_snapshot endpoint;
	route_generation *generation;
	uint8_t inbound[BUFSIZ];
	size_t inbound_size;
	struct timespec lifetime_deadline;
	struct listener_connection *next;
	size_t request_offset;
	connection_setup_short_plan short_plan;
	int socket_fd;
	listener_connection_state state;
	int timer_fd;
	struct timespec timer_deadline;
	uint64_t timer_generation;
	listener_event_source timer_source;
	listener_connection_timer timer;
	listener_connection_buffer upstream_buffer;
	bool upstream_buffer_owned;
	uint32_t upstream_events;
	int upstream_fd;
	bool upstream_read_closed;
	bool upstream_read_paused;
	bool upstream_registered;
	listener_event_source upstream_source;
	bool upstream_write_closed;
	route_waiter *waiter;
	route_waiter_status waiter_status;
	char vhost[ROUTE_ENDPOINT_TEXT_SIZE];
};
typedef struct {
	size_t count;
	bool refusal_logged;
	struct timespec refusal_logged_at;
	pid_t pids[LISTENER_WORKER_LIMIT];
} listener_workers;
typedef struct {
	conf *config;
	conf_cache *config_cache;
	const char *config_filename;
	const char *config_filename_full;
	resolver_cache *dns_cache;
	uint64_t generation_next_identity;
	route_generation_registry *generations;
	hosts_table *hosts;
	char log_filename[PATH_MAX];
	resolver_supervisor *resolver;
	route_bindings *route_bindings;
	route_resolution *route_resolution;
	route_table *routes;
	const char *working_directory;
	listener_workers workers;
} listener_context;
typedef struct {
	net_addr address;
	in_port_t port;
} listener_endpoint;
typedef struct {
	int epoll_fd;
	listener_event_source listener_source;
	bool mask_blocked;
	sigset_t previous_signal_mask;
	int resolver_fd;
	listener_event_source resolver_source;
	int route_timer_fd;
	listener_event_source route_timer_source;
	int signal_fd;
	listener_event_source signal_source;
} listener_events;
typedef struct {
	uint32_t flags;
	const listener_event_source *source;
	uint64_t source_generation;
	uint64_t timer_generation;
} listener_ready_event;
typedef struct {
	bool accept_ready;
	bool child_ready;
	listener_ready_event ready[LISTENER_EVENT_BATCH];
	size_t ready_count;
	bool reload;
	bool resolver_ready;
	bool route_timer_ready;
	bool stop;
} listener_requests;
typedef struct {
	struct timespec deadline;
	bool pressure_logged;
	bool ready;
} listener_route_runtime;
typedef struct {
	listener_endpoint endpoint;
	int fd;
} listener_socket;

/* section: functions (local) */
static bool listener_accept_error_retryable(int error) {
	switch (error) {
		case ECONNABORTED:
		case EHOSTDOWN:
		case EHOSTUNREACH:
		case ENETDOWN:
		case ENETUNREACH:
		case ENONET:
		case ENOPROTOOPT:
		case EOPNOTSUPP:
		case EPROTO:
			return true;
		default:
			return false;
	}
}

static void listener_backoff(void) {
	struct timespec backoff = { .tv_sec = 0, .tv_nsec = 100000000 };
	nanosleep(&backoff, NULL);
}

static void listener_bind_success_msg(const listener_context *context) {
	mksysmsg(MKSYS_PREFIX_ON, context->log_filename, context->config->log.level, MKSYS_LEVEL_INFORMATION, MKSYS_PARAGRAPH_END, "Bind Successful.");
	mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, context->config->log.level, MKSYS_LEVEL_INFORMATION, MKSYS_PARAGRAPH_END,
		"For more information, see log file: %s",
		context->config->log.filename
	);
}

static net_addrbundle listener_client_address_parse(const listener_client_address *addr) {
	net_addrbundle result;
	memset(&result, 0, sizeof(result));
	result.family = addr->v4.sin_family;
	const void *addroffset = NULL;
	switch (result.family) {
		case AF_INET:
			result.address = net_ntop(AF_INET, &(addr->v4.sin_addr), true);
			result.address_clean = net_ntop(AF_INET, &(addr->v4.sin_addr), false);
			result.port = ntohs(addr->v4.sin_port);
			break;
		case AF_INET6:
			addroffset = &(addr->v6.sin6_addr);
			if (memcmp(addroffset, "\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\xFF\xFF", 12) == 0) {
				result.family = AF_INET;
				addroffset = (const uint8_t *)addroffset + 12;
			}
			result.address = net_ntop(result.family, addroffset, true);
			result.address_clean = net_ntop(result.family, addroffset, false);
			result.port = ntohs(addr->v6.sin6_port);
			break;
		default:
			result.family = 0;
			break;
	}
	return result;
}

static int listener_events_add(const listener_events *events, int fd, uint32_t flags, const listener_event_source *source) {
	struct epoll_event event;
	memset(&event, 0, sizeof(event));
	event.events = flags;
	event.data.ptr = (void *)source;
	return epoll_ctl(events->epoll_fd, EPOLL_CTL_ADD, fd, &event);
}

static int listener_events_modify(const listener_events *events, int fd, uint32_t flags, const listener_event_source *source) {
	struct epoll_event event;
	memset(&event, 0, sizeof(event));
	event.events = flags;
	event.data.ptr = (void *)source;
	return epoll_ctl(events->epoll_fd, EPOLL_CTL_MOD, fd, &event);
}

static int listener_events_remove(const listener_events *events, int fd) {
	return epoll_ctl(events->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
}

static int listener_connection_timer_set(listener_connection *connection, listener_connection_timer timer, const struct timespec *expiration) {
	struct timespec effective = *expiration;
	if (timeutil_compare(&connection->lifetime_deadline, &effective) < 0) {
		effective = connection->lifetime_deadline;
		timer = LISTENER_CONNECTION_TIMER_SHORT_LIFETIME;
	}
	struct itimerspec timeout = { .it_value = effective };
	if (timerfd_settime(connection->timer_fd, TFD_TIMER_ABSTIME, &timeout, NULL) == -1) {
		return -1;
	}
	connection->timer = timer;
	connection->timer_deadline = effective;
	connection->timer_generation = connection->timer_generation == UINT64_MAX ? 1 : connection->timer_generation + 1U;
	return 0;
}

static int listener_connection_timer_arm(listener_connection *connection, listener_connection_timer timer) {
	struct timespec expiration = connection->assembly_deadline;
	if (timer == LISTENER_CONNECTION_TIMER_GRACE) {
		struct timespec now;
		struct timespec grace_expiration;
		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1 || !timeutil_add_milliseconds(&now, LISTENER_LEGACY_PING_GRACE_MS, &grace_expiration)) {
			return -1;
		}
		if (timeutil_compare(&grace_expiration, &expiration) < 0) {
			expiration = grace_expiration;
		} else {
			timer = LISTENER_CONNECTION_TIMER_ASSEMBLY;
		}
	}
	return listener_connection_timer_set(connection, timer, &expiration);
}

static int listener_connection_timer_arm_short(listener_connection *connection, listener_connection_timer timer, const struct timespec *now, uint64_t seconds) {
	struct timespec expiration;
	return timeutil_add_seconds(now, seconds, &expiration) ? listener_connection_timer_set(connection, timer, &expiration) : -1;
}

#ifdef LISTENER_TIMER_REARM_TEST
static int listener_connection_timer_test_rearm(const listener_requests *requests) {
	static bool triggered;
	if (triggered || getenv("MCRELAY_TEST_TIMER_REARM_RACE") == NULL) {
		return 0;
	}
	for (size_t ready_index = 0; ready_index < requests->ready_count; ready_index++) {
		const listener_ready_event *ready = &requests->ready[ready_index];
		if (ready->source == NULL || ready->source->kind != LISTENER_EVENT_TIMEOUT || ready->source->connection == NULL
			|| ready->source->connection->closing) {
			continue;
		}
		listener_connection *connection = ready->source->connection;
		struct timespec now;
		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
			return -1;
		}
		/* Replace the collected expiration with a readable newer generation before the timeout pass. */
		connection->lifetime_deadline = now;
		if (listener_connection_timer_set(connection, LISTENER_CONNECTION_TIMER_SHORT_LIFETIME, &now) == -1) {
			return -1;
		}
		struct pollfd timer_event = { .fd = connection->timer_fd, .events = POLLIN };
		int poll_result;
		do {
			poll_result = poll(&timer_event, 1, 1000);
		} while (poll_result == -1 && errno == EINTR);
		if (poll_result != 1 || !(timer_event.revents & POLLIN)) {
			errno = poll_result == 0 ? ETIMEDOUT : EIO;
			return -1;
		}
		sd_notify(0, "MCRELAY_TEST_TIMER_REARM=1");
		triggered = true;
		return 0;
	}
	return 0;
}
#endif

static int listener_connection_buffer_receive(listener_connection_buffer *buffer, int socket_fd, bool *read_closed, size_t *activity) {
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

static int listener_connection_buffer_send(listener_connection_buffer *buffer, int socket_fd, size_t *activity) {
	if (buffer == NULL || buffer->data == NULL || buffer->capacity == 0 || buffer->offset > buffer->capacity || buffer->size > buffer->capacity - buffer->offset
		|| activity == NULL) {
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

static int listener_connection_interest_update(const listener_events *events, int fd, uint32_t flags, const listener_event_source *source, uint32_t *current_flags, bool *registered) {
	if (flags == 0 && *registered) {
		if (listener_events_remove(events, fd) == -1) {
			return -1;
		}
		*current_flags = 0;
		*registered = false;
	} else if (flags != 0 && !*registered) {
		if (listener_events_add(events, fd, flags, source) == -1) {
			return -1;
		}
		*current_flags = flags;
		*registered = true;
	} else if (flags != 0 && flags != *current_flags) {
		if (listener_events_modify(events, fd, flags, source) == -1) {
			return -1;
		}
		*current_flags = flags;
	}
	return 0;
}

static int listener_connection_interests_update(listener_connection *connection, const listener_events *events) {
	uint32_t client_flags = 0;
	if (connection->state == LISTENER_CONNECTION_ROUTE_WAITING) {
		client_flags = EPOLLRDHUP;
	} else if (connection->state == LISTENER_CONNECTION_SHORT_RESPONDING || connection->state == LISTENER_CONNECTION_WORKER_REFUSING) {
		if (connection->upstream_buffer.size > 0) {
			client_flags |= EPOLLOUT;
		}
	} else {
		if (!connection->client_read_closed && !connection->client_read_paused) {
			client_flags |= EPOLLIN | EPOLLRDHUP;
		}
		if (connection->state == LISTENER_CONNECTION_SHORT_RELAYING && connection->upstream_buffer.size > 0) {
			client_flags |= EPOLLOUT;
		}
	}
	if (listener_connection_interest_update(events, connection->socket_fd, client_flags, &connection->client_source, &connection->client_events, &connection->client_registered) == -1) {
		return -1;
	}
	if (connection->upstream_fd == -1) {
		return 0;
	}
	uint32_t upstream_flags = 0;
	if (connection->state == LISTENER_CONNECTION_SHORT_CONNECTING) {
		upstream_flags |= EPOLLOUT | EPOLLRDHUP;
	} else if (connection->state == LISTENER_CONNECTION_SHORT_RELAYING) {
		if (!connection->upstream_read_closed && !connection->upstream_read_paused) {
			upstream_flags |= EPOLLIN | EPOLLRDHUP;
		}
		if (connection->short_plan.request_size > 0 || connection->client_buffer.size > 0) {
			upstream_flags |= EPOLLOUT;
		}
	}
	return listener_connection_interest_update(events, connection->upstream_fd, upstream_flags, &connection->upstream_source, &connection->upstream_events, &connection->upstream_registered);
}

static listener_connection *listener_connection_create(int client_fd, const listener_client_address *client_address, const listener_events *events,
	route_generation *generation) {
	listener_connection *connection = calloc(1, sizeof(*connection));
	if (connection == NULL) {
		close(client_fd);
		route_generation_release(generation);
		return NULL;
	}
	connection->address = *client_address;
	connection->client_source.connection = connection;
	connection->client_source.kind = LISTENER_EVENT_CLIENT;
	connection->generation = generation;
	connection->socket_fd = client_fd;
	connection->timer_fd = -1;
	connection->timer_source.connection = connection;
	connection->timer_source.kind = LISTENER_EVENT_TIMEOUT;
	connection->upstream_fd = -1;
	connection->upstream_source.connection = connection;
	connection->upstream_source.kind = LISTENER_EVENT_UPSTREAM;
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1 || !timeutil_add_seconds(&now, LISTENER_INITIAL_TIMEOUT_SEC, &connection->assembly_deadline)
		|| !timeutil_add_seconds(&now, LISTENER_SHORT_LIFETIME_TIMEOUT_SEC, &connection->lifetime_deadline)) {
		goto fail;
	}
	connection->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
	if (connection->timer_fd == -1 || listener_connection_timer_arm(connection, LISTENER_CONNECTION_TIMER_ASSEMBLY) == -1) {
		goto fail;
	}
	if (listener_events_add(events, connection->socket_fd, EPOLLIN | EPOLLRDHUP, &connection->client_source) == -1) {
		goto fail;
	}
	connection->client_events = EPOLLIN | EPOLLRDHUP;
	connection->client_registered = true;
	if (listener_events_add(events, connection->timer_fd, EPOLLIN, &connection->timer_source) == -1) {
		listener_events_remove(events, connection->socket_fd);
		connection->client_registered = false;
		goto fail;
	}
	return connection;
fail: {
		int saved_errno = errno;
		if (connection->timer_fd != -1) {
			close(connection->timer_fd);
		}
		close(connection->socket_fd);
		route_generation_release(connection->generation);
		free(connection);
		errno = saved_errno;
		return NULL;
	}
}

static int listener_connection_data_send(int socket_fd, const uint8_t *data, size_t size, size_t *offset, size_t *activity) {
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

static bool listener_waiter_destroy_status_apply(route_waiter_destroy_status status) {
	switch (status) {
		case ROUTE_WAITER_DESTROY_OK:
			return true;
		case ROUTE_WAITER_DESTROY_IO:
			errno = EIO;
			return false;
		case ROUTE_WAITER_DESTROY_TIME:
			errno = EOVERFLOW;
			return false;
		case ROUTE_WAITER_DESTROY_BAD_ARGUMENT:
		default:
			errno = EINVAL;
			return false;
	}
}

static bool listener_connection_destroy(listener_connection **connections, listener_connection *target, const listener_events *events, resolver_supervisor *supervisor,
	const struct timespec *now) {
	listener_connection **current = connections;
	while (*current != NULL && *current != target) {
		current = &(*current)->next;
	}
	if (*current == NULL) {
		return true;
	}
	*current = target->next;
	if (target->socket_fd != -1) {
		if (target->client_registered) {
			listener_events_remove(events, target->socket_fd);
		}
		close(target->socket_fd);
	}
	if (target->timer_fd != -1) {
		listener_events_remove(events, target->timer_fd);
		close(target->timer_fd);
	}
	if (target->upstream_fd != -1) {
		if (target->upstream_registered) {
			listener_events_remove(events, target->upstream_fd);
		}
		close(target->upstream_fd);
	}
	connection_setup_short_destroy(&target->short_plan);
	if (target->upstream_buffer_owned) {
		free(target->upstream_buffer.data);
	}
	bool result;
	if (supervisor == NULL) {
		route_waiter_dispose(target->waiter);
		result = true;
	} else {
		result = listener_waiter_destroy_status_apply(route_waiter_destroy(target->waiter, supervisor, now));
	}
	int saved_errno = errno;
	route_generation_release(target->generation);
	free(target);
	errno = saved_errno;
	return result;
}

static bool listener_connection_snapshot_prepare(listener_connection *connection, listener_context *context, connection_setup_snapshot *result) {
	if (connection == NULL || connection->generation == NULL || context == NULL || result == NULL) {
		return false;
	}
	const conf *config = route_generation_config(connection->generation);
	const char *icon_b64 = config == NULL || config->icon_b64 == NULL ? FAVICON_BASE64 : config->icon_b64;
	size_t icon_size = strlen(icon_b64);
	if (config == NULL || config->log.filename == NULL || context->working_directory == NULL || icon_size > CONF_ICON_B64MAX) {
		return false;
	}
	memset(result, 0, sizeof(*result));
	memcpy(result->icon_b64, icon_b64, icon_size + 1U);
	int log_filename_size = config->log.filename[0] == '/'
		? snprintf(result->log_filename, sizeof(result->log_filename), "%s", config->log.filename)
		: snprintf(result->log_filename, sizeof(result->log_filename), "%s/%s", context->working_directory, config->log.filename);
	if (log_filename_size < 0 || (size_t)log_filename_size >= sizeof(result->log_filename)) {
		return false;
	}
	result->log_level = config->log.level;
	if (connection->state == LISTENER_CONNECTION_INITIAL) {
		result->route_status = CONNECTION_SETUP_ROUTE_BYPASS;
	} else {
		switch (connection->waiter_status) {
			case ROUTE_WAITER_READY:
				result->endpoint = connection->endpoint;
				result->route_status = CONNECTION_SETUP_ROUTE_READY;
				break;
			case ROUTE_WAITER_NO_ROUTE:
				result->route_status = CONNECTION_SETUP_ROUTE_NO_ROUTE;
				break;
			case ROUTE_WAITER_CONTRADICTORY:
			case ROUTE_WAITER_LIMIT:
			case ROUTE_WAITER_MEMORY:
			case ROUTE_WAITER_SERVICE_UNAVAILABLE:
			case ROUTE_WAITER_TIMEOUT:
			case ROUTE_WAITER_UNAVAILABLE:
				result->route_status = CONNECTION_SETUP_ROUTE_UNAVAILABLE;
				break;
			case ROUTE_WAITER_PENDING:
			case ROUTE_WAITER_BAD_ARGUMENT:
			case ROUTE_WAITER_IO:
			case ROUTE_WAITER_TIME:
			default:
				return false;
		}
	}
	if (result->route_status != CONNECTION_SETUP_ROUTE_READY) {
		memcpy(result->endpoint.vhost, connection->vhost, strlen(connection->vhost) + 1U);
	}
	return true;
}

static size_t listener_connection_limit(void) {
	struct rlimit descriptor_limit;
	if (getrlimit(RLIMIT_NOFILE, &descriptor_limit) == -1) {
		return LISTENER_CONNECTION_LIMIT_FALLBACK;
	}
	if (descriptor_limit.rlim_cur == RLIM_INFINITY) {
		return LISTENER_CONNECTION_LIMIT;
	}
	if (descriptor_limit.rlim_cur <= LISTENER_CONNECTION_FD_RESERVE) {
		return 0;
	}
	rlim_t resource_limit = (descriptor_limit.rlim_cur - LISTENER_CONNECTION_FD_RESERVE) / LISTENER_CONNECTION_FD_COUNT;
	return resource_limit < LISTENER_CONNECTION_LIMIT ? (size_t)resource_limit : LISTENER_CONNECTION_LIMIT;
}

static listener_connection_progress listener_connection_receive(listener_connection *connection, uint32_t event_flags) {
	while (connection->inbound_size < sizeof(connection->inbound)) {
		ssize_t receive_size = recv(connection->socket_fd, connection->inbound + connection->inbound_size, sizeof(connection->inbound) - connection->inbound_size, 0);
		if (receive_size > 0) {
			connection->inbound_size += (size_t)receive_size;
			size_t packet_size;
			protocol_packet_status packet_status = protocol_packet_length(connection->inbound, connection->inbound_size, &packet_size);
			if (packet_status == PROTOCOL_PACKET_COMPLETE) {
				return protocol_identify(connection->inbound, connection->inbound_size, NULL) == PVER_UNIDENT
					? LISTENER_CONNECTION_ABORT : LISTENER_CONNECTION_READY;
			}
			if (packet_status == PROTOCOL_PACKET_INVALID || packet_size > sizeof(connection->inbound)) {
				return LISTENER_CONNECTION_ABORT;
			}
			listener_connection_timer timer = packet_status == PROTOCOL_PACKET_AMBIGUOUS ? LISTENER_CONNECTION_TIMER_GRACE : LISTENER_CONNECTION_TIMER_ASSEMBLY;
			if (listener_connection_timer_arm(connection, timer) == -1) {
				return LISTENER_CONNECTION_ABORT;
			}
			continue;
		}
		if (receive_size == 0) {
			size_t packet_size;
			return protocol_packet_length(connection->inbound, connection->inbound_size, &packet_size) == PROTOCOL_PACKET_AMBIGUOUS
				&& protocol_identify(connection->inbound, connection->inbound_size, NULL) != PVER_UNIDENT ? LISTENER_CONNECTION_READY : LISTENER_CONNECTION_ABORT;
		}
		if (errno == EINTR) {
			continue;
		}
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return event_flags & (EPOLLERR | EPOLLHUP | EPOLLRDHUP) ? LISTENER_CONNECTION_ABORT : LISTENER_CONNECTION_PENDING;
		}
		return LISTENER_CONNECTION_ABORT;
	}
	return LISTENER_CONNECTION_ABORT;
}

static bool listener_connection_route_cancelled(const listener_connection *connection, listener_event_kind kind, uint32_t event_flags) {
	return connection != NULL && connection->state == LISTENER_CONNECTION_ROUTE_WAITING && kind == LISTENER_EVENT_CLIENT
		&& (event_flags & (EPOLLERR | EPOLLHUP | EPOLLRDHUP));
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
			if (modern.version == 0 || (modern.nextstate != CLIENT_INTENT_STATUS && modern.nextstate != CLIENT_INTENT_LOGIN
				&& modern.nextstate != CLIENT_INTENT_TRANSFER)) {
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

static listener_connection_progress listener_connection_route_progress(listener_connection *connection, resolver_supervisor *supervisor, const struct timespec *now) {
	connection->waiter_status = route_waiter_progress(connection->waiter, supervisor, now);
	switch (connection->waiter_status) {
		case ROUTE_WAITER_PENDING:
			return LISTENER_CONNECTION_PENDING;
		case ROUTE_WAITER_READY:
			return route_waiter_snapshot_take(connection->waiter, &connection->endpoint) ? LISTENER_CONNECTION_READY : LISTENER_CONNECTION_FATAL;
		case ROUTE_WAITER_BAD_ARGUMENT:
			errno = EINVAL;
			return LISTENER_CONNECTION_FATAL;
		case ROUTE_WAITER_IO:
			errno = EIO;
			return LISTENER_CONNECTION_FATAL;
		case ROUTE_WAITER_TIME:
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
			return LISTENER_CONNECTION_READY;
	}
}

static bool listener_connection_route_release(listener_connection *connection, resolver_supervisor *supervisor, const struct timespec *now) {
	if (connection == NULL || connection->generation == NULL) {
		return false;
	}
	route_waiter_destroy_status destroy_status = route_waiter_destroy(connection->waiter, supervisor, now);
	bool result = destroy_status == ROUTE_WAITER_DESTROY_OK;
	if (!result) {
		errno = destroy_status == ROUTE_WAITER_DESTROY_IO ? EIO : destroy_status == ROUTE_WAITER_DESTROY_TIME ? EOVERFLOW : EINVAL;
	}
	int saved_errno = errno;
	connection->waiter = NULL;
	route_generation_release(connection->generation);
	connection->generation = NULL;
	errno = saved_errno;
	return result;
}

static listener_connection_progress listener_connection_route_start(listener_connection *connection, const listener_events *events, resolver_supervisor *supervisor,
	const struct timespec *now) {
	listener_connection_route route = listener_connection_route_parse(connection);
	connection->dispatch = route;
	if (route == LISTENER_CONNECTION_ROUTE_SHORT_LOCAL || route == LISTENER_CONNECTION_ROUTE_WORKER_BYPASS) {
		return LISTENER_CONNECTION_READY;
	}
	if (route == LISTENER_CONNECTION_ROUTE_INVALID) {
		return LISTENER_CONNECTION_ABORT;
	}
	p_proxy inbound_proxy;
	if (!protocol_proxy_socket_read(connection->socket_fd, &inbound_proxy)) {
		return LISTENER_CONNECTION_ABORT;
	}
	connection->state = LISTENER_CONNECTION_ROUTE_WAITING;
	route_waiter_create_status create_status = route_waiter_create(connection->generation, connection->vhost, &inbound_proxy, now, &connection->waiter);
	if (create_status != ROUTE_WAITER_CREATE_OK) {
		if (create_status == ROUTE_WAITER_CREATE_BAD_ARGUMENT || create_status == ROUTE_WAITER_CREATE_TIME) {
			errno = create_status == ROUTE_WAITER_CREATE_TIME ? EOVERFLOW : EINVAL;
			return LISTENER_CONNECTION_FATAL;
		}
		connection->waiter_status = create_status == ROUTE_WAITER_CREATE_LIMIT ? ROUTE_WAITER_LIMIT : ROUTE_WAITER_MEMORY;
		return LISTENER_CONNECTION_READY;
	}
	listener_connection_progress progress = listener_connection_route_progress(connection, supervisor, now);
	if (progress != LISTENER_CONNECTION_PENDING) {
		return progress;
	}
	struct timespec deadline;
	if (!route_waiter_deadline(connection->waiter, &deadline) || listener_connection_timer_set(connection, LISTENER_CONNECTION_TIMER_ROUTE, &deadline) == -1
		|| listener_connection_interests_update(connection, events) == -1) {
		return LISTENER_CONNECTION_FATAL;
	}
	return LISTENER_CONNECTION_PENDING;
}

static bool listener_connection_short_buffer_prepare(listener_connection *connection) {
	if (connection->short_plan.response == NULL || connection->short_plan.response_size == 0
		|| connection->short_plan.response_size > LISTENER_SHORT_RELAY_BUFFER_BYTES) {
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

static void listener_connection_short_log(const listener_connection *connection, bool connected) {
	const connection_setup_short_plan *plan = &connection->short_plan;
	const route_endpoint_snapshot *endpoint = &plan->snapshot.endpoint;
	const char *destination = endpoint->target_name[0] == '\0' ? endpoint->configured_address : endpoint->target_name;
	const char *source = (const char *)&plan->inbound_address.address;
	if (plan->result == CONNECTION_SETUP_EOLDCLIENT) {
		CONNECTION_SETUP_LOG(&plan->snapshot, MKSYS_LEVEL_WARNING,
			"src: %s:%d, type: motd, status: %s",
			source, plan->inbound_address.port, plan->protocol == PVER_MODERN1 ? "reject_motdrelay_13w41*" : "reject_motdrelay_oldclient"
		);
	} else if (plan->result == CONNECTION_SETUP_ENOVHOST) {
		CONNECTION_SETUP_LOG(&plan->snapshot, MKSYS_LEVEL_WARNING,
			"src: %s:%d, type: motd, vhost: %s, status: reject_vhostinvalid",
			source, plan->inbound_address.port, endpoint->vhost
		);
	} else if (plan->result == CONNECTION_SETUP_ENORECORD) {
		CONNECTION_SETUP_LOG(&plan->snapshot, MKSYS_LEVEL_WARNING,
			"src: %s:%d, type: motd, vhost: %s, status: reject_dstnoresolve",
			source, plan->inbound_address.port, endpoint->vhost
		);
	} else if (plan->result == CONNECTION_SETUP_OK) {
		CONNECTION_SETUP_LOG(&plan->snapshot, connected ? MKSYS_LEVEL_INFORMATION + 1 : MKSYS_LEVEL_WARNING,
			"src: %s:%d, type: motd, vhost: %s, dst: %s:%d, status: %s",
			source, plan->inbound_address.port, endpoint->vhost, destination, endpoint->port, connected ? "accept" : "reject_dstnoconnect"
		);
	}
}

static void listener_connection_upstream_close(listener_connection *connection, const listener_events *events) {
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

static listener_connection_progress listener_connection_short_drive(listener_connection *connection, const listener_events *events, const struct timespec *now,
	size_t activity) {
	if (timeutil_compare(now, &connection->lifetime_deadline) >= 0) {
		return LISTENER_CONNECTION_CLOSED;
	}
	if (connection->state == LISTENER_CONNECTION_SHORT_RESPONDING || connection->state == LISTENER_CONNECTION_WORKER_REFUSING) {
		if (listener_connection_buffer_send(&connection->upstream_buffer, connection->socket_fd, &activity) == -1) {
			return LISTENER_CONNECTION_CLOSED;
		}
		if (connection->upstream_buffer.size == 0) {
			return LISTENER_CONNECTION_CLOSED;
		}
		if (connection->state == LISTENER_CONNECTION_SHORT_RESPONDING && activity > 0 && listener_connection_timer_arm_short(connection, LISTENER_CONNECTION_TIMER_SHORT_IDLE, now,
			LISTENER_SHORT_RELAY_IDLE_TIMEOUT_SEC) == -1) {
			return LISTENER_CONNECTION_ABORT;
		}
		return listener_connection_interests_update(connection, events) == -1 ? LISTENER_CONNECTION_FATAL : LISTENER_CONNECTION_PENDING;
	}
	if (connection->state != LISTENER_CONNECTION_SHORT_RELAYING) {
		return listener_connection_interests_update(connection, events) == -1 ? LISTENER_CONNECTION_FATAL : LISTENER_CONNECTION_PENDING;
	}
	if (listener_connection_data_send(connection->upstream_fd, connection->short_plan.request, connection->short_plan.request_size,
		&connection->request_offset, &activity) == -1) {
		return LISTENER_CONNECTION_CLOSED;
	}
	if (connection->request_offset == connection->short_plan.request_size && connection->short_plan.request_size > 0) {
		free(connection->short_plan.request);
		connection->short_plan.request = NULL;
		connection->short_plan.request_size = 0;
		connection->request_offset = 0;
	}
	if ((connection->short_plan.request_size == 0 && listener_connection_buffer_send(&connection->client_buffer, connection->upstream_fd, &activity) == -1)
		|| listener_connection_buffer_send(&connection->upstream_buffer, connection->socket_fd, &activity) == -1) {
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
	if (connection->client_read_closed && connection->upstream_read_closed && connection->short_plan.request_size == 0 && connection->client_buffer.size == 0
		&& connection->upstream_buffer.size == 0) {
		return LISTENER_CONNECTION_CLOSED;
	}
	if (activity > 0 && listener_connection_timer_arm_short(connection, LISTENER_CONNECTION_TIMER_SHORT_IDLE, now,
		LISTENER_SHORT_RELAY_IDLE_TIMEOUT_SEC) == -1) {
		return LISTENER_CONNECTION_ABORT;
	}
	return listener_connection_interests_update(connection, events) == -1 ? LISTENER_CONNECTION_FATAL : LISTENER_CONNECTION_PENDING;
}

static listener_connection_progress listener_connection_refusal_start(listener_connection *connection, const listener_events *events, resolver_supervisor *supervisor,
	const struct timespec *now) {
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
	if (packet_size == 0 || !listener_connection_route_release(connection, supervisor, now)) {
		return LISTENER_CONNECTION_ABORT;
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
	return listener_connection_short_drive(connection, events, now, 0);
}

static listener_connection_progress listener_connection_short_failure(listener_connection *connection, const listener_events *events, const struct timespec *now) {
	if (timeutil_compare(now, &connection->lifetime_deadline) >= 0) {
		return LISTENER_CONNECTION_CLOSED;
	}
	listener_connection_short_log(connection, false);
	listener_connection_upstream_close(connection, events);
	connection->state = LISTENER_CONNECTION_SHORT_RESPONDING;
	if (listener_connection_timer_arm_short(connection, LISTENER_CONNECTION_TIMER_SHORT_IDLE, now, LISTENER_SHORT_RELAY_IDLE_TIMEOUT_SEC) == -1) {
		return LISTENER_CONNECTION_ABORT;
	}
	return listener_connection_short_drive(connection, events, now, 0);
}

static listener_connection_progress listener_connection_short_connect_complete(listener_connection *connection, const listener_events *events,
	const struct timespec *now) {
	net_connect_status status = net_connect_nonblocking_complete(connection->upstream_fd);
	if (status != NET_CONNECT_OK) {
		return listener_connection_short_failure(connection, events, now);
	}
	if (timeutil_compare(now, &connection->lifetime_deadline) >= 0) {
		return LISTENER_CONNECTION_CLOSED;
	}
	connection->state = LISTENER_CONNECTION_SHORT_RELAYING;
	connection->upstream_buffer.offset = 0;
	connection->upstream_buffer.size = 0;
	listener_connection_short_log(connection, true);
	if (listener_connection_timer_arm_short(connection, LISTENER_CONNECTION_TIMER_SHORT_IDLE, now, LISTENER_SHORT_RELAY_IDLE_TIMEOUT_SEC) == -1) {
		return LISTENER_CONNECTION_ABORT;
	}
	return LISTENER_CONNECTION_PENDING;
}

static listener_connection_progress listener_connection_short_event(listener_connection *connection, listener_event_kind kind, uint32_t event_flags,
	uint64_t source_generation, const listener_events *events, const struct timespec *now) {
	size_t activity = 0;
	if (kind == LISTENER_EVENT_CLIENT) {
		if (event_flags & EPOLLERR) {
			return LISTENER_CONNECTION_CLOSED;
		}
		if (connection->state != LISTENER_CONNECTION_SHORT_RESPONDING && connection->state != LISTENER_CONNECTION_WORKER_REFUSING
			&& (event_flags & (EPOLLIN | EPOLLHUP | EPOLLRDHUP))
			&& listener_connection_buffer_receive(&connection->client_buffer, connection->socket_fd, &connection->client_read_closed, &activity) == -1) {
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
			listener_connection_progress progress = listener_connection_short_connect_complete(connection, events, now);
			if (progress != LISTENER_CONNECTION_PENDING) {
				return progress;
			}
		}
		if (connection->state == LISTENER_CONNECTION_SHORT_RELAYING) {
			if (event_flags & EPOLLERR) {
				return LISTENER_CONNECTION_CLOSED;
			}
			if ((event_flags & (EPOLLIN | EPOLLHUP | EPOLLRDHUP))
				&& listener_connection_buffer_receive(&connection->upstream_buffer, connection->upstream_fd, &connection->upstream_read_closed, &activity) == -1) {
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
	return listener_connection_short_drive(connection, events, now, activity);
}

static listener_connection_progress listener_connection_short_start(listener_connection *connection, const listener_events *events, listener_context *context,
	const struct timespec *now) {
	connection_setup_snapshot snapshot;
	if (!listener_connection_snapshot_prepare(connection, context, &snapshot)) {
		return LISTENER_CONNECTION_ABORT;
	}
	net_addrbundle client = listener_client_address_parse(&connection->address);
	connection_setup_short_action action = connection_setup_short_prepare(&connection->short_plan, &snapshot, client, connection->inbound, connection->inbound_size);
	if (!listener_connection_route_release(connection, context->resolver, now)) {
		errno = EINVAL;
		return LISTENER_CONNECTION_FATAL;
	}
	if (action == CONNECTION_SETUP_SHORT_ABORT || !listener_connection_short_buffer_prepare(connection)) {
		return LISTENER_CONNECTION_ABORT;
	}
	if (action == CONNECTION_SETUP_SHORT_RESPOND) {
		listener_connection_short_log(connection, false);
		connection->state = LISTENER_CONNECTION_SHORT_RESPONDING;
		if (listener_connection_timer_arm_short(connection, LISTENER_CONNECTION_TIMER_SHORT_IDLE, now, LISTENER_SHORT_RELAY_IDLE_TIMEOUT_SEC) == -1) {
			return LISTENER_CONNECTION_ABORT;
		}
		return listener_connection_short_drive(connection, events, now, 0);
	}
	net_connect_status connect_status = net_connect_nonblocking(&connection->short_plan.snapshot.endpoint.address,
		connection->short_plan.snapshot.endpoint.port, &connection->upstream_fd);
	if (connect_status != NET_CONNECT_OK && connect_status != NET_CONNECT_PENDING) {
		return listener_connection_short_failure(connection, events, now);
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
		listener_connection_short_log(connection, true);
		if (listener_connection_timer_arm_short(connection, LISTENER_CONNECTION_TIMER_SHORT_IDLE, now, LISTENER_SHORT_RELAY_IDLE_TIMEOUT_SEC) == -1) {
			return LISTENER_CONNECTION_ABORT;
		}
	}
	return listener_connection_short_drive(connection, events, now, 0);
}

static listener_connection_progress listener_connection_timeout(listener_connection *connection, uint32_t event_flags, uint64_t timer_generation,
	const listener_events *events, resolver_supervisor *supervisor, const struct timespec *now) {
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
	if (timer_generation != connection->timer_generation && clock_gettime(CLOCK_MONOTONIC, &current_now) == -1) {
		return LISTENER_CONNECTION_FATAL;
	}
	/* A rearmed timer may have expired after epoll collected the stale readiness event. */
	if (timeutil_compare(&current_now, &connection->timer_deadline) < 0) {
		return LISTENER_CONNECTION_PENDING;
	}
	if (connection->timer == LISTENER_CONNECTION_TIMER_ROUTE) {
		return listener_connection_route_progress(connection, supervisor, &current_now);
	}
	if (connection->timer == LISTENER_CONNECTION_TIMER_SHORT_CONNECT) {
		return listener_connection_short_failure(connection, events, &current_now);
	}
	if (connection->timer == LISTENER_CONNECTION_TIMER_SHORT_IDLE || connection->timer == LISTENER_CONNECTION_TIMER_SHORT_LIFETIME
		|| connection->timer == LISTENER_CONNECTION_TIMER_WORKER_REFUSAL) {
		return LISTENER_CONNECTION_CLOSED;
	}
	return connection->timer == LISTENER_CONNECTION_TIMER_GRACE && protocol_identify(connection->inbound, connection->inbound_size, NULL) != PVER_UNIDENT
		? LISTENER_CONNECTION_READY : LISTENER_CONNECTION_ABORT;
}

static void listener_connections_close_except(listener_connection *connections, const listener_connection *except) {
	for (listener_connection *connection = connections; connection != NULL; connection = connection->next) {
		if (connection != except) {
			close(connection->socket_fd);
		}
		close(connection->timer_fd);
		if (connection->upstream_fd != -1) {
			close(connection->upstream_fd);
		}
	}
}

static bool listener_connections_destroy_closed(listener_connection **connections, const listener_events *events, resolver_supervisor *supervisor,
	const struct timespec *now, size_t *destroyed_count) {
	if (destroyed_count == NULL) {
		errno = EINVAL;
		return false;
	}
	*destroyed_count = 0;
	bool result = true;
	int saved_errno = 0;
	listener_connection *connection = *connections;
	while (connection != NULL) {
		listener_connection *next = connection->next;
		if (connection->closing) {
			bool destroyed = listener_connection_destroy(connections, connection, events, supervisor, now);
			if (!destroyed && result) {
				saved_errno = errno;
				result = false;
			}
			(*destroyed_count)++;
		}
		connection = next;
	}
	if (!result) {
		errno = saved_errno;
	}
	return result;
}

static bool listener_endpoint_equal(const listener_endpoint *left, const listener_endpoint *right) {
	if (left->address.family != right->address.family || left->port != right->port) {
		return false;
	}
	switch (left->address.family) {
		case AF_INET:
			return left->address.addr.v4 == right->address.addr.v4;
		case AF_INET6:
			return memcmp(left->address.addr.v6, right->address.addr.v6, sizeof(left->address.addr.v6)) == 0;
		default:
			return false;
	}
}

static bool listener_endpoint_is_wildcard(const listener_endpoint *target) {
	switch (target->address.family) {
		case AF_INET:
			return target->address.addr.v4 == INADDR_ANY;
		case AF_INET6:
			return memcmp(target->address.addr.v6, &in6addr_any, sizeof(target->address.addr.v6)) == 0;
		default:
			return false;
	}
}

static bool listener_endpoint_may_conflict(const listener_endpoint *left, const listener_endpoint *right) {
	if (left->port != right->port) {
		return false;
	}
	if (left->address.family != right->address.family) {
		return true;
	}
	return listener_endpoint_is_wildcard(left) || listener_endpoint_is_wildcard(right);
}

static listener_endpoint_status listener_endpoint_prepare(const conf *source, listener_endpoint *target) {
	target->address = net_addr_parse(source->listen.address);
	target->port = source->listen.port;
	if (target->address.family == 0) {
		return LISTENER_ENDPOINT_BAD_ADDRESS;
	}
	if (target->port == 0) {
		return LISTENER_ENDPOINT_BAD_PORT;
	}
	return LISTENER_ENDPOINT_OK;
}

static void listener_events_destroy(listener_events *events) {
	if (events->epoll_fd != -1) {
		close(events->epoll_fd);
	}
	if (events->signal_fd != -1) {
		close(events->signal_fd);
	}
	if (events->route_timer_fd != -1) {
		close(events->route_timer_fd);
	}
	if (events->mask_blocked) {
		sigprocmask(SIG_SETMASK, &events->previous_signal_mask, NULL);
	}
}

static int listener_events_socket_add(const listener_events *events, int socket_fd) {
	int socket_flags = fcntl(socket_fd, F_GETFL);
	if (socket_flags == -1 || fcntl(socket_fd, F_SETFL, socket_flags | O_NONBLOCK) == -1) {
		return -1;
	}
	return listener_events_add(events, socket_fd, EPOLLIN, &events->listener_source);
}

static int listener_events_init(listener_events *events) {
	int saved_errno;
	memset(events, 0, sizeof(*events));
	events->epoll_fd = -1;
	events->resolver_fd = -1;
	events->route_timer_fd = -1;
	events->signal_fd = -1;
	events->listener_source.kind = LISTENER_EVENT_LISTENER;
	events->resolver_source.kind = LISTENER_EVENT_RESOLVER;
	events->route_timer_source.kind = LISTENER_EVENT_ROUTE_TIMER;
	events->signal_source.kind = LISTENER_EVENT_SIGNAL;
	struct sigaction child_action = { 0 };
	sigemptyset(&child_action.sa_mask);
	child_action.sa_flags = SA_NOCLDSTOP;
	child_action.sa_handler = SIG_DFL;
	if (sigaction(SIGCHLD, &child_action, NULL) == -1) {
		return -1;
	}
	sigset_t signal_mask;
	sigemptyset(&signal_mask);
	sigaddset(&signal_mask, SIGCHLD);
	sigaddset(&signal_mask, SIGINT);
	sigaddset(&signal_mask, SIGTERM);
	sigaddset(&signal_mask, SIGUSR1);
	if (sigprocmask(SIG_BLOCK, &signal_mask, &events->previous_signal_mask) == -1) {
		return -1;
	}
	events->mask_blocked = true;
	events->signal_fd = signalfd(-1, &signal_mask, SFD_NONBLOCK | SFD_CLOEXEC);
	if (events->signal_fd == -1) {
		goto fail;
	}
	events->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (events->epoll_fd == -1) {
		goto fail;
	}
	if (listener_events_add(events, events->signal_fd, EPOLLIN, &events->signal_source) == -1) {
		goto fail;
	}
	events->route_timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (events->route_timer_fd == -1) {
		goto fail;
	}
	if (listener_events_add(events, events->route_timer_fd, EPOLLIN, &events->route_timer_source) == -1) {
		goto fail;
	}
	return 0;
fail:
	saved_errno = errno;
	listener_events_destroy(events);
	errno = saved_errno;
	return -1;
}

static int listener_events_resolver_add(listener_events *events, int resolver_fd) {
	if (events == NULL || resolver_fd < 0 || events->resolver_fd != -1) {
		errno = EINVAL;
		return -1;
	}
	if (listener_events_add(events, resolver_fd, EPOLLIN, &events->resolver_source) == -1) {
		return -1;
	}
	events->resolver_fd = resolver_fd;
	return 0;
}

static int listener_signals_read(int signal_fd, listener_requests *requests) {
	while (1) {
		struct signalfd_siginfo signal_info;
		ssize_t bytes = read(signal_fd, &signal_info, sizeof(signal_info));
		if (bytes == (ssize_t)sizeof(signal_info)) {
			switch (signal_info.ssi_signo) {
				case SIGCHLD:
					requests->child_ready = true;
					break;
				case SIGINT:
				case SIGTERM:
					requests->stop = true;
					break;
				case SIGUSR1:
					requests->reload = true;
					break;
			}
			continue;
		}
		if (bytes == -1 && errno == EINTR) {
			continue;
		}
		if (bytes == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return 0;
		}
		if (bytes != -1) {
			errno = EIO;
		}
		return -1;
	}
}

static int listener_events_wait(const listener_events *events, listener_requests *requests) {
	struct epoll_event ready_events[LISTENER_EVENT_BATCH];
	memset(requests, 0, sizeof(*requests));
	int ready_count;
	do {
		ready_count = epoll_wait(events->epoll_fd, ready_events, LISTENER_EVENT_BATCH, -1);
	} while (ready_count == -1 && errno == EINTR);
	if (ready_count == -1) {
		return -1;
	}
	for (int i = 0; i < ready_count; i++) {
		uint32_t event_flags = ready_events[i].events;
		const listener_event_source *source = ready_events[i].data.ptr;
		if (source == NULL) {
			errno = EIO;
			return -1;
		}
		switch (source->kind) {
		case LISTENER_EVENT_SIGNAL:
			if (source != &events->signal_source) {
				errno = EIO;
				return -1;
			}
			if ((event_flags & EPOLLIN) && listener_signals_read(events->signal_fd, requests) == -1) {
				return -1;
			}
			if (event_flags & (EPOLLERR | EPOLLHUP)) {
				errno = EIO;
				return -1;
			}
			break;
		case LISTENER_EVENT_LISTENER:
			if (source != &events->listener_source) {
				errno = EIO;
				return -1;
			}
			if (event_flags & (EPOLLERR | EPOLLHUP)) {
				errno = EIO;
				return -1;
			}
			if (event_flags & EPOLLIN) {
				requests->accept_ready = true;
			}
			break;
		case LISTENER_EVENT_RESOLVER:
			if (source != &events->resolver_source || events->resolver_fd == -1) {
				errno = EIO;
				return -1;
			}
			if (event_flags & (EPOLLERR | EPOLLHUP)) {
				errno = EIO;
				return -1;
			}
			if (event_flags & EPOLLIN) {
				requests->resolver_ready = true;
			}
			break;
		case LISTENER_EVENT_ROUTE_TIMER:
			if (source != &events->route_timer_source) {
				errno = EIO;
				return -1;
			}
			if (event_flags & (EPOLLERR | EPOLLHUP)) {
				errno = EIO;
				return -1;
			}
			if (event_flags & EPOLLIN) {
				requests->route_timer_ready = true;
			}
			break;
		case LISTENER_EVENT_CLIENT:
		case LISTENER_EVENT_TIMEOUT:
		case LISTENER_EVENT_UPSTREAM:
			if (source->connection == NULL || requests->ready_count >= sizeof(requests->ready) / sizeof(requests->ready[0])) {
				errno = EOVERFLOW;
				return -1;
			}
			requests->ready[requests->ready_count].flags = event_flags;
			requests->ready[requests->ready_count].source = source;
			requests->ready[requests->ready_count].source_generation = source->generation;
			requests->ready[requests->ready_count].timer_generation = source->kind == LISTENER_EVENT_TIMEOUT ? source->connection->timer_generation : 0;
			requests->ready_count++;
			break;
		default:
			errno = EIO;
			return -1;
		}
	}
	return 0;
}

static bool listener_generation_collect(listener_context *context, const struct timespec *now) {
	route_generation_registry_collect_status status = route_generation_registry_collect(context->generations, context->resolver, now);
	switch (status) {
		case ROUTE_GENERATION_REGISTRY_COLLECT_NONE:
		case ROUTE_GENERATION_REGISTRY_COLLECT_RETAINED:
		case ROUTE_GENERATION_REGISTRY_COLLECT_COLLECTED:
			return true;
		case ROUTE_GENERATION_REGISTRY_COLLECT_IO:
			errno = EIO;
			return false;
		case ROUTE_GENERATION_REGISTRY_COLLECT_TIME:
			errno = EOVERFLOW;
			return false;
		case ROUTE_GENERATION_REGISTRY_COLLECT_BAD_ARGUMENT:
		default:
			errno = EINVAL;
			return false;
	}
}

static bool listener_generation_create(listener_context *context, conf *config, hosts_table *hosts, route_table *routes, route_bindings *bindings,
	route_resolution *resolution, mksys_level failure_level, const char *failure_action, route_generation **result) {
	if (result == NULL || *result != NULL) {
		return false;
	}
	route_generation_create_status status = route_generation_create(context->generation_next_identity, config, hosts, routes, bindings, resolution, result);
	if (status == ROUTE_GENERATION_CREATE_OK) {
		return true;
	}
	LISTENER_LOG(context, failure_level,
		"Cannot own prepared proxy route generation: %s%s.",
		status == ROUTE_GENERATION_CREATE_MEMORY ? "memory allocation failed" : "invalid internal generation state", failure_action
	);
	return false;
}

static route_generation_registry_publish_status listener_generation_publish(listener_context *context, route_generation **candidate) {
	if (context == NULL || candidate == NULL || *candidate == NULL || context->resolver == NULL) {
		return ROUTE_GENERATION_REGISTRY_PUBLISH_BAD_ARGUMENT;
	}
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
		return ROUTE_GENERATION_REGISTRY_PUBLISH_TIME;
	}
	route_generation_registry_publish_status status = route_generation_registry_publish(context->generations, candidate, context->resolver, &now);
	if (*candidate != NULL) {
		return status;
	}
	route_generation *active = route_generation_registry_active(context->generations);
	if (active == NULL) {
		return ROUTE_GENERATION_REGISTRY_PUBLISH_BAD_ARGUMENT;
	}
	context->config = (conf *)route_generation_config(active);
	context->hosts = (hosts_table *)route_generation_hosts(active);
	context->route_bindings = (route_bindings *)route_generation_bindings(active);
	context->route_resolution = route_generation_resolution(active);
	context->routes = (route_table *)route_generation_routes(active);
	context->generation_next_identity = context->generation_next_identity == UINT64_MAX ? 0 : context->generation_next_identity + 1U;
	return status;
}

static const char *listener_hosts_load_error(hosts_load_status status) {
	switch (status) {
		case HOSTS_LOAD_LIMIT:
			return "entry limit reached";
		case HOSTS_LOAD_MEMORY:
			return "memory allocation failed";
		case HOSTS_LOAD_BAD_ARGUMENT:
		default:
			return "invalid loader state";
	}
}

static bool listener_hosts_prepare(listener_context *context, mksys_level failure_level, const char *failure_action, hosts_table **result) {
	if (result == NULL || *result != NULL) {
		return false;
	}
	size_t malformed_line_count = 0;
	hosts_load_status status = hosts_table_load(LISTENER_HOSTS_FILENAME, result, &malformed_line_count);
	if (status != HOSTS_LOAD_OK && status != HOSTS_LOAD_FILE_ERROR) {
		LISTENER_LOG(context, failure_level, "Cannot prepare local static host table from %s: %s%s.", LISTENER_HOSTS_FILENAME, listener_hosts_load_error(status), failure_action);
		return false;
	}
	if (*result == NULL) {
		LISTENER_LOG(context, failure_level, "Cannot prepare local static host table from %s: loader returned no table%s.", LISTENER_HOSTS_FILENAME, failure_action);
		return false;
	}
	if (status == HOSTS_LOAD_FILE_ERROR) {
		LISTENER_LOG(context, MKSYS_LEVEL_WARNING, "Cannot read local static host table from %s; using guaranteed localhost entries.", LISTENER_HOSTS_FILENAME);
	}
	if (malformed_line_count > 0) {
		LISTENER_LOG(context, MKSYS_LEVEL_WARNING,
			"Ignored %zu malformed line%s while loading local static host table from %s.",
			malformed_line_count, malformed_line_count == 1 ? "" : "s", LISTENER_HOSTS_FILENAME
		);
	}
	return true;
}

static void listener_notify_ready(void) {
	sd_notify(0, "READY=1");
}

static int listener_notify_reloading(void) {
	struct timespec timestamp;
	if (clock_gettime(CLOCK_MONOTONIC, &timestamp) == -1) {
		return -1;
	}
	if (!timeutil_valid(&timestamp)) {
		errno = EINVAL;
		return -1;
	}
	uint64_t timestamp_subsecond_usec = (uint64_t)timestamp.tv_nsec / 1000;
	if ((uint64_t)timestamp.tv_sec > (UINT64_MAX - timestamp_subsecond_usec) / 1000000) {
		errno = EOVERFLOW;
		return -1;
	}
	uint64_t timestamp_usec = (uint64_t)timestamp.tv_sec * 1000000 + timestamp_subsecond_usec;
	sd_notifyf(0, "RELOADING=1\nMONOTONIC_USEC=%" PRIu64, timestamp_usec);
	return 0;
}

static bool listener_route_bindings_prepare(listener_context *context, const route_table *routes, const hosts_table *hosts, mksys_level failure_level, const char *failure_action, route_bindings **result) {
	route_bindings_build_status status = route_bindings_build(routes, hosts, context->dns_cache, result);
	if (status == ROUTE_BINDINGS_BUILD_OK) {
		return true;
	}
	const char *reason;
	switch (status) {
		case ROUTE_BINDINGS_BUILD_LIMIT:
			reason = "resolver cache capacity reached";
			break;
		case ROUTE_BINDINGS_BUILD_MEMORY:
			reason = "memory allocation failed";
			break;
		case ROUTE_BINDINGS_BUILD_BAD_ARGUMENT:
		case ROUTE_BINDINGS_BUILD_INVALID:
		default:
			reason = "invalid internal binding state";
			break;
	}
	LISTENER_LOG(context, failure_level, "Cannot prepare proxy resolver bindings: %s%s.", reason, failure_action);
	return false;
}

static listener_route_prepare_status listener_route_resolution_prepare(listener_context *context, const route_bindings *bindings, const hosts_table *hosts,
	mksys_level failure_level, const char *failure_action, route_resolution **result) {
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
		return LISTENER_ROUTE_PREPARE_TIME_ERROR;
	}
	route_resolution_build_status status = route_resolution_build(bindings, hosts, context->dns_cache, &now, result);
	if (status == ROUTE_RESOLUTION_BUILD_OK) {
		return LISTENER_ROUTE_PREPARE_OK;
	}
	const char *reason = status == ROUTE_RESOLUTION_BUILD_MEMORY ? "memory allocation failed" : "invalid internal resolution state";
	LISTENER_LOG(context, failure_level, "Cannot prepare proxy route resolution: %s%s.", reason, failure_action);
	return LISTENER_ROUTE_PREPARE_CANDIDATE_ERROR;
}

static listener_route_prepare_status listener_generation_prepare(listener_context *context, conf **config, hosts_table **hosts, mksys_level failure_level,
	const char *failure_action, route_generation **result) {
	if (config == NULL || *config == NULL || hosts == NULL || *hosts == NULL || result == NULL || *result != NULL) {
		return LISTENER_ROUTE_PREPARE_CANDIDATE_ERROR;
	}
	route_bindings *bindings = NULL;
	route_resolution *resolution = NULL;
	route_table *routes = NULL;
	route_table_build_status route_status = route_table_build(*config, &routes);
	if (route_status != ROUTE_TABLE_BUILD_OK) {
		LISTENER_LOG(context, failure_level,
			"Cannot prepare proxy routes: %s%s.",
			route_status == ROUTE_TABLE_BUILD_MEMORY ? "memory allocation failed" : "invalid internal route state", failure_action
		);
		return LISTENER_ROUTE_PREPARE_CANDIDATE_ERROR;
	}
	if (!listener_route_bindings_prepare(context, routes, *hosts, failure_level, failure_action, &bindings)) {
		route_table_destroy(routes);
		return LISTENER_ROUTE_PREPARE_CANDIDATE_ERROR;
	}
	listener_route_prepare_status status = listener_route_resolution_prepare(context, bindings, *hosts, failure_level, failure_action, &resolution);
	if (status == LISTENER_ROUTE_PREPARE_OK && !listener_generation_create(context, *config, *hosts, routes, bindings, resolution, failure_level, failure_action, result)) {
		status = LISTENER_ROUTE_PREPARE_CANDIDATE_ERROR;
	}
	if (status == LISTENER_ROUTE_PREPARE_OK) {
		*config = NULL;
		*hosts = NULL;
		return status;
	}
	route_resolution_destroy(resolution);
	route_bindings_destroy(bindings);
	route_table_destroy(routes);
	return status;
}

static int listener_route_timer_drain(const listener_events *events) {
	uint64_t expirations;
	ssize_t bytes;
	do {
		bytes = read(events->route_timer_fd, &expirations, sizeof(expirations));
	} while (bytes == -1 && errno == EINTR);
	if (bytes == (ssize_t)sizeof(expirations)) {
		return 0;
	}
	if (bytes != -1) {
		errno = EIO;
	}
	return -1;
}

static int listener_route_timer_set(const listener_events *events, const struct timespec *deadline) {
	struct itimerspec timer;
	memset(&timer, 0, sizeof(timer));
	if (deadline != NULL) {
		timer.it_value = *deadline;
	}
	return timerfd_settime(events->route_timer_fd, TFD_TIMER_ABSTIME, &timer, NULL);
}

static int listener_route_runtime_ready(listener_context *context, listener_route_runtime *runtime, const listener_events *events, const listener_socket *listener,
	bool warmup_complete) {
	if (listener_events_socket_add(events, listener->fd) == -1) {
		return -1;
	}
	runtime->ready = true;
	listener_notify_ready();
	if (!isatty(STDOUT_FILENO)) {
		fflush(stdout);
		fflush(stderr);
		int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
		if (null_fd != -1) {
			dup2(null_fd, STDOUT_FILENO);
			dup2(null_fd, STDERR_FILENO);
			if (null_fd > STDERR_FILENO) {
				close(null_fd);
			}
		}
	}
	if (warmup_complete) {
		mksysmsg(MKSYS_PREFIX_ON, context->log_filename, context->config->log.level, MKSYS_LEVEL_INFORMATION, MKSYS_PARAGRAPH_END,
			"Initial proxy route warm-up finished; accepting connections."
		);
	} else {
		mksysmsg(MKSYS_PREFIX_ON, context->log_filename, context->config->log.level, MKSYS_LEVEL_WARNING, MKSYS_PARAGRAPH_END,
			"Initial proxy route warm-up deadline reached; accepting connections while prewarming continues."
		);
	}
	return 0;
}

static int listener_route_runtime_schedule(listener_context *context, listener_route_runtime *runtime, const listener_events *events, const listener_socket *listener,
	const struct timespec *now) {
	route_prewarm_status status = route_resolution_schedule(context->route_resolution, context->resolver, now, LISTENER_ROUTE_PREWARM_BATCH_LIMIT);
	if (status == ROUTE_PREWARM_BAD_ARGUMENT || status == ROUTE_PREWARM_IO || status == ROUTE_PREWARM_TIME) {
		errno = status == ROUTE_PREWARM_TIME ? EINVAL : status == ROUTE_PREWARM_IO ? EIO : EINVAL;
		return -1;
	}
	if (status == ROUTE_PREWARM_CAPACITY || status == ROUTE_PREWARM_MEMORY) {
		if (!runtime->pressure_logged) {
			LISTENER_LOG(context, MKSYS_LEVEL_WARNING,
				"Proxy route prewarming paused by local resolver %s pressure; it will resume after later resolver activity.",
				status == ROUTE_PREWARM_CAPACITY ? "capacity" : "memory"
			);
			runtime->pressure_logged = true;
		}
	} else if (runtime->pressure_logged) {
		LISTENER_LOG(context, MKSYS_LEVEL_INFORMATION, "Proxy route prewarming resumed after local resolver pressure.");
		runtime->pressure_logged = false;
	}
	bool deadline_reached = timeutil_compare(now, &runtime->deadline) >= 0;
	bool warmup_complete = route_resolution_warmup_complete(context->route_resolution);
	if (!runtime->ready && (warmup_complete || deadline_reached) && listener_route_runtime_ready(context, runtime, events, listener, warmup_complete) == -1) {
		return -1;
	}
	if (status == ROUTE_PREWARM_MORE) {
		return listener_route_timer_set(events, now);
	}
	if (!runtime->ready) {
		return listener_route_timer_set(events, &runtime->deadline);
	}
	return listener_route_timer_set(events, NULL);
}

static int listener_route_runtime_start(listener_route_runtime *runtime, const listener_events *events, const struct timespec *now) {
	memset(runtime, 0, sizeof(*runtime));
	if (LISTENER_ROUTE_PREWARM_BATCH_LIMIT == 0 || LISTENER_ROUTE_WARMUP_TIMEOUT_SEC == 0
		|| !timeutil_add_seconds(now, LISTENER_ROUTE_WARMUP_TIMEOUT_SEC, &runtime->deadline)) {
		errno = EINVAL;
		return -1;
	}
	return listener_route_timer_set(events, &runtime->deadline);
}

static int listener_socket_bind(listener_socket *target) {
	target->fd = net_socket(NETSOCK_BIND, target->endpoint.address.family, &(target->endpoint.address.addr), target->endpoint.port, true);
	return target->fd;
}

static void listener_socket_close(listener_socket *target) {
	if (target->fd != -1) {
		close(target->fd);
		target->fd = -1;
	}
}

static listener_socket_open_status listener_socket_open(listener_socket *target, const listener_events *events) {
	if (listener_socket_bind(target) == -1) {
		return LISTENER_SOCKET_OPEN_BIND_ERROR;
	}
	if (listener_events_socket_add(events, target->fd) == -1) {
		int saved_errno = errno;
		listener_socket_close(target);
		errno = saved_errno;
		return LISTENER_SOCKET_OPEN_EVENTS_ERROR;
	}
	return LISTENER_SOCKET_OPEN_OK;
}

static listener_socket_replace_status listener_socket_replace_conflicting(listener_socket *target, listener_socket *candidate, const listener_events *events) {
	if (listener_events_remove(events, target->fd) == -1) {
		return LISTENER_SOCKET_REPLACE_ACTIVE_ERROR;
	}
	listener_socket_close(target);
	if (listener_socket_open(candidate, events) == LISTENER_SOCKET_OPEN_OK) {
		*target = *candidate;
		return LISTENER_SOCKET_REPLACE_OK;
	}
	int candidate_errno = errno;
	if (listener_socket_open(target, events) != LISTENER_SOCKET_OPEN_OK) {
		return LISTENER_SOCKET_REPLACE_ROLLBACK_ERROR;
	}
	errno = candidate_errno;
	return LISTENER_SOCKET_REPLACE_CANDIDATE_ERROR;
}

static listener_socket_replace_status listener_socket_replace(listener_socket *target, const listener_endpoint *endpoint, const listener_events *events) {
	listener_socket candidate = {
		.endpoint = *endpoint,
		.fd = -1
	};
	listener_socket_open_status open_status = listener_socket_open(&candidate, events);
	if (open_status != LISTENER_SOCKET_OPEN_OK) {
		/* Same-port address transitions may require closing the active socket before binding the candidate. */
		if (open_status == LISTENER_SOCKET_OPEN_BIND_ERROR && listener_endpoint_may_conflict(&target->endpoint, &candidate.endpoint) && errno == NET_EBIND) {
			return listener_socket_replace_conflicting(target, &candidate, events);
		}
		return LISTENER_SOCKET_REPLACE_CANDIDATE_ERROR;
	}
	if (listener_events_remove(events, target->fd) == -1) {
		int saved_errno = errno;
		listener_events_remove(events, candidate.fd);
		listener_socket_close(&candidate);
		errno = saved_errno;
		return LISTENER_SOCKET_REPLACE_ACTIVE_ERROR;
	}
	listener_socket_close(target);
	*target = candidate;
	return LISTENER_SOCKET_REPLACE_OK;
}

static int listener_reload(listener_context *context, listener_socket *listener, const listener_events *events) {
	uint8_t config_maxlevel = context->config->log.level;
	int result = 0;
	char config_logfull_old[PATH_MAX];
	snprintf(config_logfull_old, sizeof(config_logfull_old), "%s", context->log_filename);
	MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_INFORMATION,
		"Reloading config from file: %s",
		context->config_filename
	);
	hosts_table *hosts_candidate = NULL;
	bool hosts_prepared = listener_hosts_prepare(context, MKSYS_LEVEL_WARNING, ", keeping the existing table", &hosts_candidate);
	conf_cache config_cache_candidate = { 0 };
	conf *config_candidate = NULL;
	route_generation *generation_candidate = NULL;
	bool primary_published = false;
	conf_read_status read_status = config_read(context->config_filename_full, context->config_cache, &config_cache_candidate, &config_candidate);
	switch (read_status) {
		case CONF_READ_CHANGED: {
			listener_endpoint candidate_endpoint;
			listener_endpoint_status endpoint_status = listener_endpoint_prepare(config_candidate, &candidate_endpoint);
			if (endpoint_status == LISTENER_ENDPOINT_BAD_ADDRESS) {
				MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
					"Error in configurations: Invalid candidate bind address, will keep your old configurations."
				);
				break;
			}
			if (endpoint_status == LISTENER_ENDPOINT_BAD_PORT) {
				MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
					"Error in configurations: Invalid candidate bind port, will keep your old configurations."
				);
				break;
			}
			char config_logfull_candidate[PATH_MAX];
			resolve_path(config_candidate->log.filename, context->working_directory, config_logfull_candidate, sizeof(config_logfull_candidate));
			if (log_file_validate(config_logfull_candidate) == -1) {
				MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
					"Cannot write candidate log to \"%s\", will keep your old configurations.",
					config_candidate->log.filename
				);
				break;
			}
			if (!config_icon_load(config_candidate, config_logfull_old, config_maxlevel, "will keep your old configurations")) {
				break;
			}
			if (hosts_candidate == NULL && !hosts_table_clone(context->hosts, &hosts_candidate)) {
				MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
					"Cannot clone the existing local static host table for the candidate generation, will keep your old configurations."
				);
				break;
			}
			listener_route_prepare_status prepare_status = listener_generation_prepare(context, &config_candidate, &hosts_candidate, MKSYS_LEVEL_WARNING,
				", will keep your old configurations", &generation_candidate);
			if (prepare_status == LISTENER_ROUTE_PREPARE_TIME_ERROR) {
				MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_CRITICAL,
					"Cannot sample the monotonic clock while preparing candidate proxy route resolution: %s",
					strerror(errno)
				);
				result = -1;
				break;
			}
			if (prepare_status != LISTENER_ROUTE_PREPARE_OK) {
				break;
			}
			if (!listener_endpoint_equal(&listener->endpoint, &candidate_endpoint)) {
				net_addrp candidate_address = net_ntop(candidate_endpoint.address.family, &(candidate_endpoint.address.addr), true);
				listener_socket_replace_status replace_status = listener_socket_replace(listener, &candidate_endpoint, events);
				if (replace_status == LISTENER_SOCKET_REPLACE_CANDIDATE_ERROR) {
					MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
						"Cannot activate candidate listening endpoint %s:%d, will keep your old configurations.",
						(char *)&candidate_address, candidate_endpoint.port
					);
					break;
				}
				if (replace_status == LISTENER_SOCKET_REPLACE_ACTIVE_ERROR) {
					MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_CRITICAL,
						"Cannot replace active listening socket: %s",
						strerror(errno)
					);
					result = -1;
					break;
				}
				if (replace_status == LISTENER_SOCKET_REPLACE_ROLLBACK_ERROR) {
					MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_CRITICAL,
						"Cannot activate candidate listening endpoint %s:%d or restore the active listening socket.",
						(char *)&candidate_address, candidate_endpoint.port
					);
					result = -1;
					break;
				}
				MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_INFORMATION,
					"Listening endpoint changed to %s:%d.",
					(char *)&candidate_address, candidate_endpoint.port
				);
			}
			route_generation_registry_publish_status publish_status = listener_generation_publish(context, &generation_candidate);
			if (publish_status != ROUTE_GENERATION_REGISTRY_PUBLISH_OK) {
				MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_CRITICAL,
					"Cannot publish the prepared proxy route generation: %s.",
					publish_status == ROUTE_GENERATION_REGISTRY_PUBLISH_BLOCKED ? "a retired generation is still pinned" : "invalid internal generation state"
				);
				result = -1;
				break;
			}
			snprintf(context->log_filename, sizeof(context->log_filename), "%s", config_logfull_candidate);
			config_cache_commit(context->config_cache, &config_cache_candidate);
			primary_published = true;
			MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_INFORMATION,
				"Configuration reloaded."
			);
			break;
		}
		case CONF_READ_UNCHANGED:
			MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_INFORMATION,
				"Configuration file unchanged."
			);
			break;
		case CONF_READ_ERROR:
			switch (errno) {
				case CONF_EROPENFAIL:
				case CONF_EROPENEMPTY:
				case CONF_EROPENLARGE:
				case CONF_ERMEMORY:
				case CONF_ERPARSE:
				case CONF_ECMEMORY:
				case CONF_ECLISTENPORT:
				case CONF_ECPROXY:
					MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
						"%s%s%s",
						config_errmsg((conf_error)errno), (errno == CONF_EROPENFAIL || errno == CONF_EROPENEMPTY) ? context->config_filename : "", ", will keep your old configurations"
					);
					break;
				case CONF_ECPROXYDUP:
					config_log_duplicate_error(config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING, ", will keep your old configurations");
					break;
				default:
					MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
						"Error in processing configurations: Unknown error occurred, code: %d, will keep your old configurations",
						errno
					);
					break;
			}
	}
	if (generation_candidate != NULL) {
		if (result == 0 && hosts_prepared && hosts_candidate == NULL && !hosts_table_clone(route_generation_hosts(generation_candidate), &hosts_candidate)) {
			MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
				"Cannot preserve the candidate local static host table after route-generation activation failed."
			);
		}
		route_generation_release(generation_candidate);
		generation_candidate = NULL;
	}
	config_destroy(config_candidate);
	config_candidate = NULL;
	if (result == 0 && !primary_published && ((hosts_prepared && hosts_candidate != NULL) || read_status == CONF_READ_UNCHANGED)) {
		bool publish_hosts = hosts_prepared && hosts_candidate != NULL;
		if (!config_clone(context->config, &config_candidate)) {
			MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
				"Cannot clone the active configuration for a replacement route generation, keeping the existing generation."
			);
		} else if (hosts_candidate == NULL && !hosts_table_clone(context->hosts, &hosts_candidate)) {
			MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
				"Cannot clone the active local static host table for a replacement route generation, keeping the existing generation."
			);
		} else {
			if (read_status == CONF_READ_UNCHANGED) {
				config_icon_load(config_candidate, config_logfull_old, config_maxlevel, "keeping existing icon");
			}
			listener_route_prepare_status prepare_status = listener_generation_prepare(context, &config_candidate, &hosts_candidate, MKSYS_LEVEL_WARNING,
				", keeping the existing generation", &generation_candidate);
			if (prepare_status == LISTENER_ROUTE_PREPARE_TIME_ERROR) {
				MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_CRITICAL,
					"Cannot sample the monotonic clock while preparing local static host route resolution: %s",
					strerror(errno)
				);
				result = -1;
			} else if (prepare_status == LISTENER_ROUTE_PREPARE_OK) {
				route_generation_registry_publish_status publish_status = listener_generation_publish(context, &generation_candidate);
				if (publish_status != ROUTE_GENERATION_REGISTRY_PUBLISH_OK) {
					MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_CRITICAL,
						"Cannot publish the replacement proxy route generation: %s.",
						publish_status == ROUTE_GENERATION_REGISTRY_PUBLISH_BLOCKED ? "a retired generation is still pinned" : "invalid internal generation state"
					);
					result = -1;
				} else if (publish_hosts) {
					MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_INFORMATION, "Local static host table reloaded.");
				}
			}
		}
	}
	route_generation_release(generation_candidate);
	config_destroy(config_candidate);
	config_cache_destroy(&config_cache_candidate);
	hosts_table_destroy(hosts_candidate);
	return result;
}

static void listener_resolver_destroy(listener_context *context) {
	resolver_supervisor_destroy(context->resolver);
	context->resolver = NULL;
}

static void listener_resolver_dispose_in_child(listener_context *context) {
	resolver_supervisor_dispose_in_child(context->resolver);
	context->resolver = NULL;
}

static int listener_resolver_events_process(listener_context *context, listener_connection *connections, const struct timespec *now) {
	resolver_supervisor_event_status status = resolver_supervisor_events_process(context->resolver, now);
	if (status != RESOLVER_SUPERVISOR_EVENT_OK) {
		errno = status == RESOLVER_SUPERVISOR_EVENT_TIME ? EINVAL : EIO;
		return -1;
	}
	resolver_supervisor_completion completion = { 0 };
	while (resolver_supervisor_completion_take(context->resolver, &completion)) {
		route_resolution_completion_status completion_status = route_generation_registry_completion_observe(context->generations, &completion, context->resolver, now);
		bool waiter_invalid = false;
		for (listener_connection *connection = connections; connection != NULL; connection = connection->next) {
			if (connection->waiter == NULL || connection->closing) {
				continue;
			}
			route_waiter_completion_status waiter_status = route_waiter_completion_observe(connection->waiter, &completion);
			if (waiter_status == ROUTE_WAITER_COMPLETION_BAD_ARGUMENT) {
				waiter_invalid = true;
			}
		}
		resolver_supervisor_completion_destroy(&completion);
		if (completion_status == ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT || completion_status == ROUTE_RESOLUTION_COMPLETION_IO
			|| completion_status == ROUTE_RESOLUTION_COMPLETION_TIME || waiter_invalid) {
			errno = completion_status == ROUTE_RESOLUTION_COMPLETION_IO ? EIO : completion_status == ROUTE_RESOLUTION_COMPLETION_TIME ? EOVERFLOW : EINVAL;
			return -1;
		}
	}
	return 0;
}

static int listener_resolver_init(listener_context *context, listener_events *events) {
	struct timespec now;
	context->dns_cache = resolver_cache_create();
	if (context->dns_cache == NULL || clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
		return -1;
	}
	context->resolver = resolver_supervisor_create(&events->previous_signal_mask, &now);
	if (context->resolver == NULL || listener_events_resolver_add(events, resolver_supervisor_event_fd(context->resolver)) == -1) {
		return -1;
	}
	return 0;
}

static int listener_resolver_shutdown(listener_context *context) {
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1 || !resolver_supervisor_shutdown(context->resolver, &now)) {
		return -1;
	}
	return 0;
}

static void listener_worker_refusal_log(listener_context *context) {
	listener_workers *workers = &context->workers;
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
		return;
	}
	struct timespec next_log;
	if (workers->refusal_logged && timeutil_add_seconds(&workers->refusal_logged_at, LISTENER_WORKER_LOG_INTERVAL_SEC, &next_log)
		&& timeutil_compare(&now, &next_log) < 0) {
		return;
	}
	LISTENER_LOG(context, MKSYS_LEVEL_WARNING, "Worker process limit reached; refusing a new LOGIN or TRANSFER connection until a worker exits.");
	workers->refusal_logged = true;
	workers->refusal_logged_at = now;
}

static void listener_worker_route_state_dispose(listener_context *context) {
	route_generation_registry_dispose_in_child(context->generations);
	context->generations = NULL;
	context->config = NULL;
	context->hosts = NULL;
	context->route_bindings = NULL;
	context->route_resolution = NULL;
	context->routes = NULL;
	resolver_cache_destroy(context->dns_cache);
	context->dns_cache = NULL;
}

static int listener_worker_signals_restore(const sigset_t *signal_mask) {
	struct sigaction action;
	memset(&action, 0, sizeof(action));
	sigemptyset(&action.sa_mask);
	action.sa_handler = SIG_IGN;
	if (sigaction(SIGUSR1, &action, NULL) == -1) {
		return -1;
	}
	action.sa_handler = SIG_DFL;
	if (sigaction(SIGINT, &action, NULL) == -1 || sigaction(SIGTERM, &action, NULL) == -1) {
		return -1;
	}
	return sigprocmask(SIG_SETMASK, signal_mask, NULL);
}

static exit_code listener_worker_run(int client_fd, const listener_client_address *client_address, const uint8_t *inbound, size_t inbound_size,
	const connection_setup_snapshot *snapshot, listener_socket *listener, const listener_events *events, pid_t listener_pid, listener_context *context) {
	if (prctl(PR_SET_NAME, LISTENER_WORKER_PROCESS_NAME) == -1) {
		CONNECTION_SETUP_LOG(snapshot, MKSYS_LEVEL_WARNING, "Cannot set worker process name: %s", strerror(errno));
	}
	close(events->epoll_fd);
	close(events->route_timer_fd);
	close(events->signal_fd);
	listener_socket_close(listener);
	listener_resolver_dispose_in_child(context);
	if (prctl(PR_SET_PDEATHSIG, SIGTERM) == -1) {
		CONNECTION_SETUP_LOG(snapshot, MKSYS_LEVEL_WARNING, "Cannot configure worker parent-death signal: %s", strerror(errno));
		listener_worker_route_state_dispose(context);
		return EXITCODE_INTERNAL;
	}
	if (getppid() != listener_pid) {
		listener_worker_route_state_dispose(context);
		return EXITCODE_OK;
	}
	if (listener_worker_signals_restore(&events->previous_signal_mask) == -1) {
		CONNECTION_SETUP_LOG(snapshot, MKSYS_LEVEL_WARNING, "Cannot restore worker signal state: %s", strerror(errno));
		listener_worker_route_state_dispose(context);
		return EXITCODE_INTERNAL;
	}
	listener_worker_route_state_dispose(context);
	net_addrbundle addrbundle_inbound_client = listener_client_address_parse(client_address);
	uint8_t seed[CONNECTION_SETUP_LONG_PENDING_MAX];
	size_t seed_size;
	int socket_outbound;
	connection_setup_status setup_status = connection_setup_long_prepared(client_fd, &socket_outbound, snapshot, addrbundle_inbound_client, inbound, inbound_size, seed, &seed_size);
	if (setup_status == CONNECTION_SETUP_OK) {
		net_relay(client_fd, socket_outbound, seed, seed_size);
	}
	return EXITCODE_OK;
}

static int listener_workers_reap(listener_context *context) {
	listener_workers *workers = &context->workers;
	for (size_t index = 0; index < workers->count;) {
		pid_t result;
		do {
			result = waitpid(workers->pids[index], NULL, WNOHANG);
		} while (result == -1 && errno == EINTR);
		if (result == workers->pids[index] || (result == -1 && errno == ECHILD)) {
			workers->count--;
			workers->pids[index] = workers->pids[workers->count];
			continue;
		}
		if (result == -1) {
			return -1;
		}
		index++;
	}
	return 0;
}

static listener_connection_progress listener_connection_dispatch(listener_connection *connections, listener_connection *connection, listener_socket *listener, const listener_events *events,
	pid_t listener_pid, listener_context *context, const struct timespec *now) {
	if (context->workers.count >= LISTENER_WORKER_LIMIT) {
		listener_worker_refusal_log(context);
		return listener_connection_refusal_start(connection, events, context->resolver, now);
	}
	connection_setup_snapshot snapshot;
	if (!listener_connection_snapshot_prepare(connection, context, &snapshot)
		|| !listener_connection_route_release(connection, context->resolver, now)) {
		LISTENER_LOG(context, MKSYS_LEVEL_WARNING, "Cannot prepare a self-contained worker handoff.");
		connection->closing = true;
		return LISTENER_CONNECTION_PENDING;
	}
	pid_t worker_pid = fork();
	if (worker_pid > 0) {
		context->workers.pids[context->workers.count] = worker_pid;
		context->workers.count++;
		connection->closing = true;
		return LISTENER_CONNECTION_PENDING;
	}
	if (worker_pid < 0) {
		int saved_errno = errno;
		connection->closing = true;
		LISTENER_LOG(context, MKSYS_LEVEL_WARNING, "Cannot create worker process: %s", strerror(saved_errno));
		listener_backoff();
		return LISTENER_CONNECTION_PENDING;
	}
	listener_connections_close_except(connections, connection);
	_exit(listener_worker_run(connection->socket_fd, &connection->address, connection->inbound, connection->inbound_size, &snapshot, listener, events, listener_pid, context));
}

static listener_connection_progress listener_connection_ready(listener_connection *connections, listener_connection *connection, listener_socket *listener,
	const listener_events *events, pid_t listener_pid, listener_context *context, const struct timespec *now) {
	if (connection->dispatch == LISTENER_CONNECTION_ROUTE_SHORT_LOCAL || connection->dispatch == LISTENER_CONNECTION_ROUTE_SHORT_WAIT) {
		return listener_connection_short_start(connection, events, context, now);
	}
	if (connection->dispatch == LISTENER_CONNECTION_ROUTE_WORKER_BYPASS || connection->dispatch == LISTENER_CONNECTION_ROUTE_WORKER_WAIT) {
		return listener_connection_dispatch(connections, connection, listener, events, listener_pid, context, now);
	}
	return LISTENER_CONNECTION_ABORT;
}

static int listener_connections_route_progress(listener_connection *connections, listener_socket *listener, const listener_events *events, pid_t listener_pid,
	listener_context *context, const struct timespec *now) {
	for (listener_connection *connection = connections; connection != NULL; connection = connection->next) {
		if (connection->closing || connection->state != LISTENER_CONNECTION_ROUTE_WAITING) {
			continue;
		}
		listener_connection_progress progress = listener_connection_route_progress(connection, context->resolver, now);
		if (progress == LISTENER_CONNECTION_READY) {
			progress = listener_connection_ready(connections, connection, listener, events, listener_pid, context, now);
		} else if (progress == LISTENER_CONNECTION_FATAL) {
			return -1;
		}
		if (progress == LISTENER_CONNECTION_FATAL) {
			return -1;
		}
		if (progress == LISTENER_CONNECTION_ABORT || progress == LISTENER_CONNECTION_CLOSED) {
			connection->closing = true;
		}
	}
	return 0;
}

static exit_code listener_loop(listener_context *context, listener_socket *listener) {
	listener_events events;
	if (listener_events_init(&events) == -1) {
		LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot initialize listener event loop: %s", strerror(errno));
		listener_socket_close(listener);
		return EXITCODE_INTERNAL;
	}
	context->generations = route_generation_registry_create();
	if (context->generations == NULL) {
		LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot initialize proxy route generation ownership: memory allocation failed.");
		listener_events_destroy(&events);
		listener_socket_close(listener);
		return EXITCODE_INTERNAL;
	}
	if (!listener_hosts_prepare(context, MKSYS_LEVEL_CRITICAL, "", &context->hosts)) {
		listener_events_destroy(&events);
		listener_socket_close(listener);
		return EXITCODE_INTERNAL;
	}
	if (listener_resolver_init(context, &events) == -1) {
		LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot initialize resolver runtime: %s", strerror(errno));
		listener_resolver_destroy(context);
		listener_events_destroy(&events);
		listener_socket_close(listener);
		return EXITCODE_INTERNAL;
	}
	if (!listener_route_bindings_prepare(context, context->routes, context->hosts, MKSYS_LEVEL_CRITICAL, "", &context->route_bindings)) {
		listener_resolver_destroy(context);
		listener_events_destroy(&events);
		listener_socket_close(listener);
		return EXITCODE_INTERNAL;
	}
	listener_route_prepare_status resolution_status = listener_route_resolution_prepare(context, context->route_bindings, context->hosts, MKSYS_LEVEL_CRITICAL, "",
		&context->route_resolution);
	if (resolution_status != LISTENER_ROUTE_PREPARE_OK) {
		if (resolution_status == LISTENER_ROUTE_PREPARE_TIME_ERROR) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot sample the monotonic clock while preparing proxy route resolution: %s", strerror(errno));
		}
		listener_resolver_destroy(context);
		listener_events_destroy(&events);
		listener_socket_close(listener);
		return EXITCODE_INTERNAL;
	}
	route_generation *initial_generation = NULL;
	if (!listener_generation_create(context, context->config, context->hosts, context->routes, context->route_bindings, context->route_resolution,
		MKSYS_LEVEL_CRITICAL, "", &initial_generation)) {
		listener_resolver_destroy(context);
		listener_events_destroy(&events);
		listener_socket_close(listener);
		return EXITCODE_INTERNAL;
	}
	route_generation_registry_publish_status initial_publish_status = listener_generation_publish(context, &initial_generation);
	if (initial_publish_status != ROUTE_GENERATION_REGISTRY_PUBLISH_OK) {
		LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot publish the initial proxy route generation: invalid internal generation state.");
		route_generation_release(initial_generation);
		context->config = NULL;
		context->hosts = NULL;
		context->route_bindings = NULL;
		context->route_resolution = NULL;
		context->routes = NULL;
		listener_resolver_destroy(context);
		listener_events_destroy(&events);
		listener_socket_close(listener);
		return EXITCODE_INTERNAL;
	}
	listener_bind_success_msg(context);
	struct timespec route_now;
	listener_route_runtime route_runtime;
	if (clock_gettime(CLOCK_MONOTONIC, &route_now) == -1 || listener_route_runtime_start(&route_runtime, &events, &route_now) == -1
		|| listener_route_runtime_schedule(context, &route_runtime, &events, listener, &route_now) == -1) {
		LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot start proxy route prewarming: %s", strerror(errno));
		listener_resolver_destroy(context);
		listener_events_destroy(&events);
		listener_socket_close(listener);
		return EXITCODE_INTERNAL;
	}
	exit_code exitcode = EXITCODE_OK;
	size_t connection_count = 0;
	const size_t connection_limit = listener_connection_limit();
	listener_connection *connections = NULL;
	pid_t listener_pid = getpid();
	bool reload_pending = false;
	bool shutting_down = false;
	while (1) {
		listener_requests requests;
		if (listener_events_wait(&events, &requests) == -1) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Listener event loop failed: %s", strerror(errno));
			exitcode = EXITCODE_INTERNAL;
			break;
		}
		/* Client cancellation wins when route completion and peer shutdown are ready in the same epoll batch. */
		for (size_t ready_index = 0; ready_index < requests.ready_count; ready_index++) {
			const listener_ready_event *ready = &requests.ready[ready_index];
			if (listener_connection_route_cancelled(ready->source->connection, ready->source->kind, ready->flags)) {
				ready->source->connection->closing = true;
			}
		}
		if (requests.resolver_ready || requests.route_timer_ready) {
			if (clock_gettime(CLOCK_MONOTONIC, &route_now) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot sample the monotonic clock for route resolution: %s", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				break;
			}
			if (requests.resolver_ready && listener_resolver_events_process(context, connections, &route_now) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Resolver event processing failed: %s", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				break;
			}
			if (requests.route_timer_ready && listener_route_timer_drain(&events) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot consume the route warm-up timer: %s", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				break;
			}
		}
		if (requests.child_ready && listener_workers_reap(context) == -1) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot reap a worker process: %s", strerror(errno));
			exitcode = EXITCODE_INTERNAL;
			break;
		}
		if (requests.stop && !shutting_down) {
			if (clock_gettime(CLOCK_MONOTONIC, &route_now) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot sample the monotonic clock while closing listener connections: %s", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				break;
			}
			int connection_destroy_errno = 0;
			while (connections != NULL) {
				if (!listener_connection_destroy(&connections, connections, &events, context->resolver, &route_now) && connection_destroy_errno == 0) {
					connection_destroy_errno = errno;
				}
			}
			connection_count = 0;
			if (connection_destroy_errno != 0) {
				errno = connection_destroy_errno;
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot release connection route interests during shutdown: %s", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				break;
			}
			if (listener_route_timer_set(&events, NULL) == -1 || listener_resolver_shutdown(context) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot shut down resolver runtime: %s", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				break;
			}
			shutting_down = true;
		}
		if (shutting_down) {
			if (resolver_supervisor_shutdown_complete(context->resolver)) {
				break;
			}
			continue;
		}
		if (requests.reload) {
			reload_pending = true;
		}
		if (requests.resolver_ready && listener_connections_route_progress(connections, listener, &events, listener_pid, context, &route_now) == -1) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Connection route resolution failed: %s", strerror(errno));
			exitcode = EXITCODE_INTERNAL;
			break;
		}
		if (!listener_generation_collect(context, &route_now)) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot collect a retired proxy route generation: %s", strerror(errno));
			exitcode = EXITCODE_INTERNAL;
			break;
		}
		bool reload_processed = false;
		if (route_runtime.ready && reload_pending && route_generation_registry_retired(context->generations) == NULL) {
			if (listener_notify_reloading() == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot create systemd reload timestamp: %s", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				break;
			}
			int reload_result = listener_reload(context, listener, &events);
			/* Complete the reload handshake before acting on a fatal result; systemd observes the subsequent listener exit separately. */
			listener_notify_ready();
			reload_pending = false;
			if (reload_result == -1) {
				exitcode = EXITCODE_INTERNAL;
				break;
			}
			reload_processed = true;
			route_runtime.pressure_logged = false;
		}
		bool route_activity = requests.accept_ready || requests.ready_count > 0 || requests.reload || requests.resolver_ready || requests.route_timer_ready || reload_processed;
		if (route_activity) {
			if (clock_gettime(CLOCK_MONOTONIC, &route_now) == -1
				|| listener_route_runtime_schedule(context, &route_runtime, &events, listener, &route_now) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Proxy route prewarming failed: %s", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				break;
			}
		}
		/* Consume socket data before timers from the same epoll batch, then reject only a still-current deadline. */
		for (int timeout_pass = 0; timeout_pass <= 1; timeout_pass++) {
			if (timeout_pass == 1 && clock_gettime(CLOCK_MONOTONIC, &route_now) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot sample the monotonic clock while processing connection deadlines: %s", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				goto cleanup;
			}
			for (size_t ready_index = 0; ready_index < requests.ready_count; ready_index++) {
				const listener_event_source *source = requests.ready[ready_index].source;
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
					progress = listener_connection_timeout(connection, requests.ready[ready_index].flags, requests.ready[ready_index].timer_generation, &events,
						context->resolver, &route_now);
				} else if (connection->state == LISTENER_CONNECTION_INITIAL) {
					progress = kind == LISTENER_EVENT_CLIENT ? listener_connection_receive(connection, requests.ready[ready_index].flags) : LISTENER_CONNECTION_PENDING;
				} else if (connection->state == LISTENER_CONNECTION_ROUTE_WAITING) {
					progress = listener_connection_route_cancelled(connection, kind, requests.ready[ready_index].flags)
						? LISTENER_CONNECTION_CLOSED : LISTENER_CONNECTION_PENDING;
				} else {
					progress = listener_connection_short_event(connection, kind, requests.ready[ready_index].flags,
						requests.ready[ready_index].source_generation, &events, &route_now);
				}
				if (progress == LISTENER_CONNECTION_READY && connection->state == LISTENER_CONNECTION_INITIAL) {
					progress = listener_connection_route_start(connection, &events, context->resolver, &route_now);
				}
				if (progress == LISTENER_CONNECTION_PENDING && listener_connection_route_cancelled(connection, kind, requests.ready[ready_index].flags)) {
					progress = LISTENER_CONNECTION_CLOSED;
				}
				if (progress == LISTENER_CONNECTION_READY) {
					progress = listener_connection_ready(connections, connection, listener, &events, listener_pid, context, &route_now);
				}
				if (progress == LISTENER_CONNECTION_FATAL) {
					LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Connection state processing failed: %s", strerror(errno));
					exitcode = EXITCODE_INTERNAL;
					goto cleanup;
				} else if (progress == LISTENER_CONNECTION_ABORT) {
					net_addrbundle client = listener_client_address_parse(&connection->address);
					LISTENER_LOG(context, MKSYS_LEVEL_WARNING,
						"src: %s:%d, status: %s",
						(char *)&client.address, client.port, connection->state == LISTENER_CONNECTION_INITIAL ? "abort_init" : "abort_short"
					);
					connection->closing = true;
				} else if (progress == LISTENER_CONNECTION_CLOSED) {
					connection->closing = true;
				}
			}
#ifdef LISTENER_TIMER_REARM_TEST
			if (timeout_pass == 0 && listener_connection_timer_test_rearm(&requests) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot run the timer rearm regression hook: %s", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				goto cleanup;
			}
#endif
		}
		size_t destroyed_count;
		if (!listener_connections_destroy_closed(&connections, &events, context->resolver, &route_now, &destroyed_count)) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot release closed connection route interests: %s", strerror(errno));
			exitcode = EXITCODE_INTERNAL;
			break;
		}
		if (destroyed_count > connection_count) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Listener connection accounting failed.");
			exitcode = EXITCODE_INTERNAL;
			break;
		}
		connection_count -= destroyed_count;
		if (!listener_generation_collect(context, &route_now)) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot collect a retired proxy route generation after connection processing: %s", strerror(errno));
			exitcode = EXITCODE_INTERNAL;
			break;
		}
		if (route_runtime.ready && reload_pending && route_generation_registry_retired(context->generations) == NULL) {
			if (clock_gettime(CLOCK_MONOTONIC, &route_now) == -1 || listener_route_timer_set(&events, &route_now) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot resume a deferred configuration reload: %s", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				break;
			}
		}
		if (!route_runtime.ready || !requests.accept_ready) {
			continue;
		}
		for (size_t accept_attempt = 0; accept_attempt < LISTENER_ACCEPT_BATCH; accept_attempt++) {
			listener_client_address client_address;
			socklen_t address_length = sizeof(client_address);
			int client_fd = accept4(listener->fd, (struct sockaddr *)&client_address, &address_length, SOCK_CLOEXEC | SOCK_NONBLOCK);
			if (client_fd == -1) {
				if (errno == EINTR) {
					continue;
				}
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					break;
				}
				if (listener_accept_error_retryable(errno)) {
					continue;
				}
				if (errno == EMFILE || errno == ENFILE) {
					LISTENER_LOG(context, MKSYS_LEVEL_WARNING, "Cannot accept client connection: %s", strerror(errno));
					listener_backoff();
					break;
				}
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot accept client connection: %s", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				goto cleanup;
			}
			if (connection_count >= connection_limit || context->workers.count >= connection_limit - connection_count) {
				close(client_fd);
				continue;
			}
			route_generation *generation = route_generation_registry_active_retain(context->generations);
			if (generation == NULL) {
				close(client_fd);
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot retain the active route generation for a client connection.");
				exitcode = EXITCODE_INTERNAL;
				goto cleanup;
			}
			listener_connection *connection = listener_connection_create(client_fd, &client_address, &events, generation);
			if (connection == NULL) {
				int saved_errno = errno;
				LISTENER_LOG(context, MKSYS_LEVEL_WARNING, "Cannot track client connection: %s", strerror(saved_errno));
				listener_backoff();
				break;
			}
			connection->next = connections;
			connections = connection;
			connection_count++;
		}
	}
cleanup: {
	while (connections != NULL) {
		listener_connection_destroy(&connections, connections, &events, NULL, NULL);
	}
	listener_resolver_destroy(context);
	listener_events_destroy(&events);
	listener_socket_close(listener);
	return exitcode;
}
}

/* section: functions (exported) */
exit_code listener_run(conf *config, conf_cache *config_cache, const char *config_filename, const char *config_filename_full, const char *working_directory, const char *log_filename) {
	listener_context context = {
		.config = config,
		.config_cache = config_cache,
		.config_filename = config_filename,
		.config_filename_full = config_filename_full,
		.generation_next_identity = 1,
		.working_directory = working_directory
	};
	snprintf(context.log_filename, sizeof(context.log_filename), "%s", log_filename);
	if (prctl(PR_SET_NAME, LISTENER_PROCESS_NAME) == -1) {
		LISTENER_LOG(&context, MKSYS_LEVEL_WARNING, "Cannot set listener process name: %s", strerror(errno));
	}
	bool generation_owned;
	exit_code exitcode;
	listener_socket listener = { .fd = -1 };
	listener_endpoint_status endpoint_status = listener_endpoint_prepare(context.config, &listener.endpoint);
	if (endpoint_status == LISTENER_ENDPOINT_BAD_ADDRESS) {
		LISTENER_LOG(&context, MKSYS_LEVEL_CRITICAL, "Error: Invalid bind address!");
		exitcode = EXITCODE_BINDFAIL;
		goto cleanup;
	}
	if (endpoint_status == LISTENER_ENDPOINT_BAD_PORT) {
		LISTENER_LOG(&context, MKSYS_LEVEL_CRITICAL, "Error: Invalid bind port!");
		exitcode = EXITCODE_BADPORT;
		goto cleanup;
	}
	route_table_build_status route_status = route_table_build(context.config, &context.routes);
	if (route_status != ROUTE_TABLE_BUILD_OK) {
		LISTENER_LOG(&context, MKSYS_LEVEL_CRITICAL,
			"Cannot prepare proxy routes: %s.",
			route_status == ROUTE_TABLE_BUILD_MEMORY ? "memory allocation failed" : "invalid internal route state"
		);
		exitcode = EXITCODE_INTERNAL;
		goto cleanup;
	}
	net_addrp bindaddrp = net_ntop(listener.endpoint.address.family, &(listener.endpoint.address.addr), true);
	LISTENER_LOG(&context, MKSYS_LEVEL_INFORMATION, "Binding on %s:%d...", (char *)&bindaddrp, listener.endpoint.port);
	if (listener_socket_bind(&listener) == -1) {
		LISTENER_LOG(&context, MKSYS_LEVEL_CRITICAL, "Bind Failed!");
		exitcode = EXITCODE_BINDFAIL;
		goto cleanup;
	}
	exitcode = listener_loop(&context, &listener);
cleanup:
	generation_owned = route_generation_registry_active(context.generations) != NULL;
	route_generation_registry_destroy(context.generations);
	if (!generation_owned) {
		route_resolution_destroy(context.route_resolution);
		route_bindings_destroy(context.route_bindings);
		hosts_table_destroy(context.hosts);
		route_table_destroy(context.routes);
		config_destroy(context.config);
	}
	config_cache_destroy(context.config_cache);
	resolver_cache_destroy(context.dns_cache);
	return exitcode;
}
