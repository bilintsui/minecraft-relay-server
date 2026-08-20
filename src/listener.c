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
#include <systemd/sd-daemon.h>
#include <time.h>
#include <unistd.h>

/* section: headers (project) */
#include "basic.h"
#include "config.h"
#include "connsetup.h"
#include "define/exitcode.h"
#include "hosts.h"
#include "log.h"
#include "network.h"
#include "protocol/common.h"
#include "protocol/handshake.h"
#include "protocol/handshake_legacy.h"
#include "protocol/proxy.h"
#include "resolver_cache.h"
#include "resolver_supervisor.h"
#include "route_bindings.h"
#include "route_generation.h"
#include "route_generation_registry.h"
#include "route_resolution.h"
#include "route_table.h"
#include "route_waiter.h"

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

/* initial packet */
#ifndef LISTENER_INITIAL_TIMEOUT_SEC
#define LISTENER_INITIAL_TIMEOUT_SEC	10
#endif
#ifndef LISTENER_LEGACY_PING_GRACE_MS
#define LISTENER_LEGACY_PING_GRACE_MS	100
#endif

/* logging macro */
#define LISTENER_LOG(ctx, lvl, ...)	mksysmsg(MKSYS_PREFIX_ON, (ctx)->log_filename, (ctx)->config->log.level, lvl, __VA_ARGS__)
#define LISTENER_LOG_TERMINAL(ctx, lvl, ...)	mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, (ctx)->config->log.level, lvl, __VA_ARGS__)

/* section: types */
enum listener_endpoint_status {
	LISTENER_ENDPOINT_OK,
	LISTENER_ENDPOINT_BAD_ADDRESS,
	LISTENER_ENDPOINT_BAD_PORT
};
enum listener_connection_progress {
	LISTENER_CONNECTION_ABORT,
	LISTENER_CONNECTION_FATAL,
	LISTENER_CONNECTION_PENDING,
	LISTENER_CONNECTION_READY
};
enum listener_connection_route {
	LISTENER_CONNECTION_ROUTE_BYPASS,
	LISTENER_CONNECTION_ROUTE_INVALID,
	LISTENER_CONNECTION_ROUTE_WAIT
};
enum listener_connection_state {
	LISTENER_CONNECTION_INITIAL,
	LISTENER_CONNECTION_ROUTE_WAITING
};
enum listener_connection_timer {
	LISTENER_CONNECTION_TIMER_ASSEMBLY,
	LISTENER_CONNECTION_TIMER_GRACE,
	LISTENER_CONNECTION_TIMER_ROUTE
};
enum listener_event_kind {
	LISTENER_EVENT_CLIENT,
	LISTENER_EVENT_LISTENER,
	LISTENER_EVENT_RESOLVER,
	LISTENER_EVENT_ROUTE_TIMER,
	LISTENER_EVENT_SIGNAL,
	LISTENER_EVENT_TIMEOUT
};
enum listener_route_prepare_status {
	LISTENER_ROUTE_PREPARE_OK,
	LISTENER_ROUTE_PREPARE_CANDIDATE_ERROR,
	LISTENER_ROUTE_PREPARE_TIME_ERROR
};
enum listener_socket_open_status {
	LISTENER_SOCKET_OPEN_OK,
	LISTENER_SOCKET_OPEN_BIND_ERROR,
	LISTENER_SOCKET_OPEN_EVENTS_ERROR
};
enum listener_socket_replace_status {
	LISTENER_SOCKET_REPLACE_OK,
	LISTENER_SOCKET_REPLACE_CANDIDATE_ERROR,
	LISTENER_SOCKET_REPLACE_ACTIVE_ERROR,
	LISTENER_SOCKET_REPLACE_ROLLBACK_ERROR
};
typedef union {
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
} listener_client_address;
typedef struct listener_connection listener_connection;
typedef struct {
	listener_connection *connection;
	enum listener_event_kind kind;
} listener_event_source;
struct listener_connection {
	listener_client_address address;
	struct timespec assembly_deadline;
	listener_event_source client_source;
	bool client_registered;
	bool closing;
	route_endpoint_snapshot endpoint;
	route_generation *generation;
	uint8_t inbound[BUFSIZ];
	size_t inbound_size;
	struct listener_connection *next;
	int socket_fd;
	enum listener_connection_state state;
	int timer_fd;
	uint64_t timer_generation;
	listener_event_source timer_source;
	enum listener_connection_timer timer;
	route_waiter *waiter;
	route_waiter_status waiter_status;
	char vhost[ROUTE_ENDPOINT_TEXT_SIZE];
};
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
	uint64_t timer_generation;
} listener_ready_event;
typedef struct {
	bool accept_ready;
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
	LISTENER_LOG(context, MKSYS_LEVEL_INFORMATION, "Bind Successful.\n\n");
	LISTENER_LOG_TERMINAL(context, MKSYS_LEVEL_INFORMATION, "For more information, see log file: %s\n\n", context->config->log.filename);
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

static int listener_events_remove(const listener_events *events, int fd) {
	return epoll_ctl(events->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
}

static bool listener_connection_time_add_milliseconds(const struct timespec *source, uint64_t milliseconds, struct timespec *result) {
	if (source == NULL || result == NULL || source->tv_sec < 0 || source->tv_nsec < 0 || source->tv_nsec >= 1000000000L || milliseconds > UINT64_MAX / 1000000U) {
		return false;
	}
	uint64_t nanoseconds = milliseconds * 1000000U;
	uint64_t added_seconds = nanoseconds / 1000000000U;
	uint64_t added_nanoseconds = nanoseconds % 1000000000U;
	if ((uintmax_t)source->tv_sec > UINTMAX_MAX - added_seconds) {
		return false;
	}
	uintmax_t seconds = (uintmax_t)source->tv_sec + added_seconds;
	long result_nanoseconds = source->tv_nsec + (long)added_nanoseconds;
	if (result_nanoseconds >= 1000000000L) {
		if (seconds == UINTMAX_MAX) {
			return false;
		}
		seconds++;
		result_nanoseconds -= 1000000000L;
	}
	time_t converted = (time_t)seconds;
	if (converted < 0 || (uintmax_t)converted != seconds) {
		return false;
	}
	result->tv_sec = converted;
	result->tv_nsec = result_nanoseconds;
	return true;
}

static int listener_connection_timer_set(listener_connection *connection, enum listener_connection_timer timer, const struct timespec *expiration) {
	struct itimerspec timeout = { .it_value = *expiration };
	if (timerfd_settime(connection->timer_fd, TFD_TIMER_ABSTIME, &timeout, NULL) == -1) {
		return -1;
	}
	connection->timer = timer;
	connection->timer_generation = connection->timer_generation == UINT64_MAX ? 1 : connection->timer_generation + 1U;
	return 0;
}

static int listener_connection_timer_arm(listener_connection *connection, enum listener_connection_timer timer) {
	struct timespec expiration = connection->assembly_deadline;
	if (timer == LISTENER_CONNECTION_TIMER_GRACE) {
		struct timespec now;
		struct timespec grace_expiration;
		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1 || !listener_connection_time_add_milliseconds(&now, LISTENER_LEGACY_PING_GRACE_MS, &grace_expiration)) {
			return -1;
		}
		if (grace_expiration.tv_sec < expiration.tv_sec || (grace_expiration.tv_sec == expiration.tv_sec && grace_expiration.tv_nsec < expiration.tv_nsec)) {
			expiration = grace_expiration;
		} else {
			timer = LISTENER_CONNECTION_TIMER_ASSEMBLY;
		}
	}
	return listener_connection_timer_set(connection, timer, &expiration);
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
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1 || !listener_connection_time_add_milliseconds(&now, (uint64_t)LISTENER_INITIAL_TIMEOUT_SEC * 1000U,
		&connection->assembly_deadline)) {
		goto fail;
	}
	connection->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
	if (connection->timer_fd == -1 || listener_connection_timer_arm(connection, LISTENER_CONNECTION_TIMER_ASSEMBLY) == -1) {
		goto fail;
	}
	if (listener_events_add(events, connection->socket_fd, EPOLLIN | EPOLLRDHUP, &connection->client_source) == -1) {
		goto fail;
	}
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

static void listener_connection_destroy(listener_connection **connections, listener_connection *target, const listener_events *events, resolver_supervisor *supervisor,
	const struct timespec *now) {
	listener_connection **current = connections;
	while (*current != NULL && *current != target) {
		current = &(*current)->next;
	}
	if (*current == NULL) {
		return;
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
	route_waiter_destroy(target->waiter, supervisor, now);
	route_generation_release(target->generation);
	free(target);
}

static bool listener_connection_handoff_prepare(listener_connection *connection, listener_context *context, const struct timespec *now, connsetup_snapshot *result) {
	if (connection == NULL || connection->generation == NULL || context == NULL || now == NULL || result == NULL) {
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
		result->route_status = CONNSETUP_ROUTE_BYPASS;
	} else {
		switch (connection->waiter_status) {
			case ROUTE_WAITER_READY:
				result->endpoint = connection->endpoint;
				result->route_status = CONNSETUP_ROUTE_READY;
				break;
			case ROUTE_WAITER_NO_ROUTE:
				result->route_status = CONNSETUP_ROUTE_NO_ROUTE;
				break;
			case ROUTE_WAITER_CONTRADICTORY:
			case ROUTE_WAITER_LIMIT:
			case ROUTE_WAITER_MEMORY:
			case ROUTE_WAITER_SERVICE_UNAVAILABLE:
			case ROUTE_WAITER_TIMEOUT:
			case ROUTE_WAITER_UNAVAILABLE:
				result->route_status = CONNSETUP_ROUTE_UNAVAILABLE;
				break;
			case ROUTE_WAITER_PENDING:
			case ROUTE_WAITER_BAD_ARGUMENT:
			case ROUTE_WAITER_IO:
			case ROUTE_WAITER_TIME:
			default:
				return false;
		}
	}
	if (result->route_status != CONNSETUP_ROUTE_READY) {
		memcpy(result->endpoint.vhost, connection->vhost, strlen(connection->vhost) + 1U);
	}
	bool waiter_destroyed = route_waiter_destroy(connection->waiter, context->resolver, now);
	connection->waiter = NULL;
	route_generation_release(connection->generation);
	connection->generation = NULL;
	return waiter_destroyed;
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

static enum listener_connection_progress listener_connection_receive(listener_connection *connection, uint32_t event_flags) {
	while (connection->inbound_size < sizeof(connection->inbound)) {
		ssize_t receive_size = recv(connection->socket_fd, connection->inbound + connection->inbound_size, sizeof(connection->inbound) - connection->inbound_size, 0);
		if (receive_size > 0) {
			connection->inbound_size += (size_t)receive_size;
			size_t packet_size;
			enum protocol_packet_status packet_status = protocol_packet_length(connection->inbound, connection->inbound_size, &packet_size);
			if (packet_status == PROTOCOL_PACKET_COMPLETE) {
				return protocol_identify(connection->inbound, connection->inbound_size, NULL) == PVER_UNIDENT
					? LISTENER_CONNECTION_ABORT : LISTENER_CONNECTION_READY;
			}
			if (packet_status == PROTOCOL_PACKET_INVALID || packet_size > sizeof(connection->inbound)) {
				return LISTENER_CONNECTION_ABORT;
			}
			enum listener_connection_timer timer = packet_status == PROTOCOL_PACKET_AMBIGUOUS ? LISTENER_CONNECTION_TIMER_GRACE : LISTENER_CONNECTION_TIMER_ASSEMBLY;
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

static enum listener_connection_route listener_connection_route_parse(listener_connection *connection) {
	uint8_t protocol = protocol_identify(connection->inbound, connection->inbound_size, NULL);
	const char *source = NULL;
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
			break;
		case PVER_LEGACYM3:
			legacy_motd = packet_read_legacy_motd(connection->inbound);
			source = legacy_motd.address;
			break;
		case PVER_MODERN2:
			modern = packet_read((void *)connection->inbound, (void *)(connection->inbound + connection->inbound_size));
			if (modern.version == 0 || (modern.nextstate != CLIENT_INTENT_STATUS && modern.nextstate != CLIENT_INTENT_LOGIN
				&& modern.nextstate != CLIENT_INTENT_TRANSFER)) {
				packet_destroy(modern);
				return LISTENER_CONNECTION_ROUTE_INVALID;
			}
			source = modern.address;
			break;
		case PVER_ORIGPRO:
		case PVER_LEGACYL1:
		case PVER_LEGACYL3:
		case PVER_LEGACYM1:
		case PVER_LEGACYM2:
		case PVER_MODERN1:
			return LISTENER_CONNECTION_ROUTE_BYPASS;
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
	return valid ? LISTENER_CONNECTION_ROUTE_WAIT : LISTENER_CONNECTION_ROUTE_INVALID;
}

static enum listener_connection_progress listener_connection_route_progress(listener_connection *connection, resolver_supervisor *supervisor, const struct timespec *now) {
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

static enum listener_connection_progress listener_connection_route_start(listener_connection *connection, const listener_events *events, resolver_supervisor *supervisor,
	const struct timespec *now) {
	enum listener_connection_route route = listener_connection_route_parse(connection);
	if (route == LISTENER_CONNECTION_ROUTE_BYPASS) {
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
	enum listener_connection_progress progress = listener_connection_route_progress(connection, supervisor, now);
	if (progress != LISTENER_CONNECTION_PENDING) {
		return progress;
	}
	struct timespec deadline;
	if (!route_waiter_deadline(connection->waiter, &deadline) || listener_connection_timer_set(connection, LISTENER_CONNECTION_TIMER_ROUTE, &deadline) == -1
		|| listener_events_remove(events, connection->socket_fd) == -1) {
		return LISTENER_CONNECTION_FATAL;
	}
	connection->client_registered = false;
	return LISTENER_CONNECTION_PENDING;
}

static enum listener_connection_progress listener_connection_timeout(listener_connection *connection, uint32_t event_flags, uint64_t timer_generation,
	resolver_supervisor *supervisor, const struct timespec *now) {
	if (!(event_flags & EPOLLIN) || (event_flags & (EPOLLERR | EPOLLHUP))) {
		return LISTENER_CONNECTION_ABORT;
	}
	if (timer_generation != connection->timer_generation) {
		return LISTENER_CONNECTION_PENDING;
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
	if (connection->timer == LISTENER_CONNECTION_TIMER_ROUTE) {
		return listener_connection_route_progress(connection, supervisor, now);
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
	}
}

static size_t listener_connections_destroy_closed(listener_connection **connections, const listener_events *events, resolver_supervisor *supervisor,
	const struct timespec *now) {
	size_t destroyed_count = 0;
	listener_connection *connection = *connections;
	while (connection != NULL) {
		listener_connection *next = connection->next;
		if (connection->closing) {
			listener_connection_destroy(connections, connection, events, supervisor, now);
			destroyed_count++;
		}
		connection = next;
	}
	return destroyed_count;
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

static enum listener_endpoint_status listener_endpoint_prepare(const conf *source, listener_endpoint *target) {
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
	struct sigaction child_action;
	memset(&child_action, 0, sizeof(child_action));
	sigemptyset(&child_action.sa_mask);
	child_action.sa_handler = SIG_IGN;
	if (sigaction(SIGCHLD, &child_action, NULL) == -1) {
		return -1;
	}
	sigset_t signal_mask;
	sigemptyset(&signal_mask);
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
			if (source->connection == NULL || requests->ready_count >= sizeof(requests->ready) / sizeof(requests->ready[0])) {
				errno = EOVERFLOW;
				return -1;
			}
			requests->ready[requests->ready_count].flags = event_flags;
			requests->ready[requests->ready_count].source = source;
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

static bool listener_generation_create(listener_context *context, conf *config, hosts_table *hosts, route_table *routes, route_bindings *bindings,
	route_resolution *resolution, uint8_t failure_level, const char *failure_action, route_generation **result) {
	if (result == NULL || *result != NULL) {
		return false;
	}
	route_generation_create_status status = route_generation_create(context->generation_next_identity, config, hosts, routes, bindings, resolution, result);
	if (status == ROUTE_GENERATION_CREATE_OK) {
		return true;
	}
	LISTENER_LOG(context, failure_level, "Cannot own prepared proxy route generation: %s%s.\n",
		status == ROUTE_GENERATION_CREATE_MEMORY ? "memory allocation failed" : "invalid internal generation state", failure_action);
	return false;
}

static route_generation_registry_publish_status listener_generation_publish(listener_context *context, route_generation **candidate) {
	if (context == NULL || candidate == NULL || *candidate == NULL) {
		return ROUTE_GENERATION_REGISTRY_PUBLISH_BAD_ARGUMENT;
	}
	route_generation_registry_publish_status status = route_generation_registry_publish(context->generations, *candidate);
	if (status != ROUTE_GENERATION_REGISTRY_PUBLISH_OK) {
		return status;
	}
	*candidate = NULL;
	route_generation *active = route_generation_registry_active(context->generations);
	context->config = (conf *)route_generation_config(active);
	context->hosts = (hosts_table *)route_generation_hosts(active);
	context->route_bindings = (route_bindings *)route_generation_bindings(active);
	context->route_resolution = route_generation_resolution(active);
	context->routes = (route_table *)route_generation_routes(active);
	context->generation_next_identity = context->generation_next_identity == UINT64_MAX ? 0 : context->generation_next_identity + 1U;
	return ROUTE_GENERATION_REGISTRY_PUBLISH_OK;
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

static bool listener_hosts_prepare(listener_context *context, uint8_t failure_level, const char *failure_action, hosts_table **result) {
	if (result == NULL || *result != NULL) {
		return false;
	}
	size_t malformed_line_count = 0;
	hosts_load_status status = hosts_table_load(LISTENER_HOSTS_FILENAME, result, &malformed_line_count);
	if (status != HOSTS_LOAD_OK && status != HOSTS_LOAD_FILE_ERROR) {
		LISTENER_LOG(context, failure_level, "Cannot prepare local static host table from %s: %s%s.\n", LISTENER_HOSTS_FILENAME, listener_hosts_load_error(status), failure_action);
		return false;
	}
	if (*result == NULL) {
		LISTENER_LOG(context, failure_level, "Cannot prepare local static host table from %s: loader returned no table%s.\n", LISTENER_HOSTS_FILENAME, failure_action);
		return false;
	}
	if (status == HOSTS_LOAD_FILE_ERROR) {
		LISTENER_LOG(context, MKSYS_LEVEL_WARNING, "Cannot read local static host table from %s; using guaranteed localhost entries.\n", LISTENER_HOSTS_FILENAME);
	}
	if (malformed_line_count > 0) {
		LISTENER_LOG(context, MKSYS_LEVEL_WARNING, "Ignored %zu malformed line%s while loading local static host table from %s.\n", malformed_line_count,
			malformed_line_count == 1 ? "" : "s", LISTENER_HOSTS_FILENAME);
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
	if (timestamp.tv_sec < 0 || timestamp.tv_nsec < 0) {
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

static bool listener_route_bindings_prepare(listener_context *context, const route_table *routes, const hosts_table *hosts, uint8_t failure_level, const char *failure_action,
	route_bindings **result) {
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
	LISTENER_LOG(context, failure_level, "Cannot prepare proxy resolver bindings: %s%s.\n", reason, failure_action);
	return false;
}

static enum listener_route_prepare_status listener_route_resolution_prepare(listener_context *context, const route_bindings *bindings, const hosts_table *hosts,
	uint8_t failure_level, const char *failure_action, route_resolution **result) {
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
		return LISTENER_ROUTE_PREPARE_TIME_ERROR;
	}
	route_resolution_build_status status = route_resolution_build(bindings, hosts, context->dns_cache, &now, result);
	if (status == ROUTE_RESOLUTION_BUILD_OK) {
		return LISTENER_ROUTE_PREPARE_OK;
	}
	const char *reason = status == ROUTE_RESOLUTION_BUILD_MEMORY ? "memory allocation failed" : "invalid internal resolution state";
	LISTENER_LOG(context, failure_level, "Cannot prepare proxy route resolution: %s%s.\n", reason, failure_action);
	return LISTENER_ROUTE_PREPARE_CANDIDATE_ERROR;
}

static enum listener_route_prepare_status listener_generation_prepare(listener_context *context, conf **config, hosts_table **hosts, uint8_t failure_level,
	const char *failure_action, route_generation **result) {
	if (config == NULL || *config == NULL || hosts == NULL || *hosts == NULL || result == NULL || *result != NULL) {
		return LISTENER_ROUTE_PREPARE_CANDIDATE_ERROR;
	}
	route_bindings *bindings = NULL;
	route_resolution *resolution = NULL;
	route_table *routes = NULL;
	route_table_build_status route_status = route_table_build(*config, &routes);
	if (route_status != ROUTE_TABLE_BUILD_OK) {
		LISTENER_LOG(context, failure_level, "Cannot prepare proxy routes: %s%s.\n",
			route_status == ROUTE_TABLE_BUILD_MEMORY ? "memory allocation failed" : "invalid internal route state", failure_action);
		return LISTENER_ROUTE_PREPARE_CANDIDATE_ERROR;
	}
	if (!listener_route_bindings_prepare(context, routes, *hosts, failure_level, failure_action, &bindings)) {
		route_table_destroy(routes);
		return LISTENER_ROUTE_PREPARE_CANDIDATE_ERROR;
	}
	enum listener_route_prepare_status status = listener_route_resolution_prepare(context, bindings, *hosts, failure_level, failure_action, &resolution);
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

static bool listener_route_time_add_seconds(const struct timespec *timestamp, uint64_t seconds, struct timespec *result) {
	if (timestamp == NULL || result == NULL || timestamp->tv_sec < 0 || timestamp->tv_nsec < 0 || timestamp->tv_nsec >= 1000000000L
		|| (uintmax_t)timestamp->tv_sec > UINTMAX_MAX - seconds) {
		return false;
	}
	uintmax_t result_seconds = (uintmax_t)timestamp->tv_sec + seconds;
	time_t converted = (time_t)result_seconds;
	if (converted < 0 || (uintmax_t)converted != result_seconds) {
		return false;
	}
	result->tv_sec = converted;
	result->tv_nsec = timestamp->tv_nsec;
	return true;
}

static int listener_route_time_compare(const struct timespec *left, const struct timespec *right) {
	if (left->tv_sec != right->tv_sec) {
		return left->tv_sec < right->tv_sec ? -1 : 1;
	}
	if (left->tv_nsec != right->tv_nsec) {
		return left->tv_nsec < right->tv_nsec ? -1 : 1;
	}
	return 0;
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
		fclose(stdout);
		fclose(stderr);
	}
	if (warmup_complete) {
		LISTENER_LOG(context, MKSYS_LEVEL_INFORMATION, "Initial proxy route warm-up finished; accepting connections.\n");
	} else {
		LISTENER_LOG(context, MKSYS_LEVEL_WARNING, "Initial proxy route warm-up deadline reached; accepting connections while prewarming continues.\n");
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
			LISTENER_LOG(context, MKSYS_LEVEL_WARNING, "Proxy route prewarming paused by local resolver %s pressure; it will resume after later resolver activity.\n",
				status == ROUTE_PREWARM_CAPACITY ? "capacity" : "memory");
			runtime->pressure_logged = true;
		}
	} else if (runtime->pressure_logged) {
		LISTENER_LOG(context, MKSYS_LEVEL_INFORMATION, "Proxy route prewarming resumed after local resolver pressure.\n");
		runtime->pressure_logged = false;
	}
	bool deadline_reached = listener_route_time_compare(now, &runtime->deadline) >= 0;
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
		|| !listener_route_time_add_seconds(now, LISTENER_ROUTE_WARMUP_TIMEOUT_SEC, &runtime->deadline)) {
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

static enum listener_socket_open_status listener_socket_open(listener_socket *target, const listener_events *events) {
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

static enum listener_socket_replace_status listener_socket_replace_conflicting(listener_socket *target, listener_socket *candidate, const listener_events *events) {
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

static enum listener_socket_replace_status listener_socket_replace(listener_socket *target, const listener_endpoint *endpoint, const listener_events *events) {
	listener_socket candidate = {
		.endpoint = *endpoint,
		.fd = -1
	};
	enum listener_socket_open_status open_status = listener_socket_open(&candidate, events);
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
	mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_INFORMATION,
		"Reloading config from file: %s\n",
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
			enum listener_endpoint_status endpoint_status = listener_endpoint_prepare(config_candidate, &candidate_endpoint);
			if (endpoint_status == LISTENER_ENDPOINT_BAD_ADDRESS) {
				mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
					"Error in configurations: Invalid candidate bind address, will keep your old configurations.\n"
				);
				break;
			}
			if (endpoint_status == LISTENER_ENDPOINT_BAD_PORT) {
				mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
					"Error in configurations: Invalid candidate bind port, will keep your old configurations.\n"
				);
				break;
			}
			char config_logfull_candidate[PATH_MAX];
			resolve_path(config_candidate->log.filename, context->working_directory, config_logfull_candidate, sizeof(config_logfull_candidate));
			if (log_file_validate(config_logfull_candidate) == -1) {
				mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
					"Cannot write candidate log to \"%s\", will keep your old configurations.\n",
					config_candidate->log.filename
				);
				break;
			}
			if (!config_icon_load(config_candidate, config_logfull_old, config_maxlevel, "will keep your old configurations")) {
				break;
			}
			if (hosts_candidate == NULL && !hosts_table_clone(context->hosts, &hosts_candidate)) {
				mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
					"Cannot clone the existing local static host table for the candidate generation, will keep your old configurations.\n");
				break;
			}
			enum listener_route_prepare_status prepare_status = listener_generation_prepare(context, &config_candidate, &hosts_candidate, MKSYS_LEVEL_WARNING,
				", will keep your old configurations", &generation_candidate);
			if (prepare_status == LISTENER_ROUTE_PREPARE_TIME_ERROR) {
				mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_CRITICAL,
					"Cannot sample the monotonic clock while preparing candidate proxy route resolution: %s\n", strerror(errno));
				result = -1;
				break;
			}
			if (prepare_status != LISTENER_ROUTE_PREPARE_OK) {
				break;
			}
			if (!listener_endpoint_equal(&listener->endpoint, &candidate_endpoint)) {
				net_addrp candidate_address = net_ntop(candidate_endpoint.address.family, &(candidate_endpoint.address.addr), true);
				enum listener_socket_replace_status replace_status = listener_socket_replace(listener, &candidate_endpoint, events);
				if (replace_status == LISTENER_SOCKET_REPLACE_CANDIDATE_ERROR) {
					mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
						"Cannot activate candidate listening endpoint %s:%d, will keep your old configurations.\n",
						(char *)&candidate_address, candidate_endpoint.port
					);
					break;
				}
				if (replace_status == LISTENER_SOCKET_REPLACE_ACTIVE_ERROR) {
					mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_CRITICAL,
						"Cannot replace active listening socket: %s\n",
						strerror(errno)
					);
					result = -1;
					break;
				}
				if (replace_status == LISTENER_SOCKET_REPLACE_ROLLBACK_ERROR) {
					mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_CRITICAL,
						"Cannot activate candidate listening endpoint %s:%d or restore the active listening socket.\n",
						(char *)&candidate_address, candidate_endpoint.port
					);
					result = -1;
					break;
				}
				mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_INFORMATION,
					"Listening endpoint changed to %s:%d.\n",
					(char *)&candidate_address, candidate_endpoint.port
				);
			}
			route_generation_registry_publish_status publish_status = listener_generation_publish(context, &generation_candidate);
			if (publish_status != ROUTE_GENERATION_REGISTRY_PUBLISH_OK) {
				mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_CRITICAL,
					"Cannot publish the prepared proxy route generation: %s.\n",
					publish_status == ROUTE_GENERATION_REGISTRY_PUBLISH_BLOCKED ? "a retired generation is still pinned" : "invalid internal generation state");
				result = -1;
				break;
			}
			snprintf(context->log_filename, sizeof(context->log_filename), "%s", config_logfull_candidate);
			config_cache_commit(context->config_cache, &config_cache_candidate);
			primary_published = true;
			mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_INFORMATION,
				"Configuration reloaded.\n"
			);
			break;
		}
		case CONF_READ_UNCHANGED:
			mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_INFORMATION,
				"Configuration file unchanged.\n"
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
					mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
						"%s%s%s\n",
						config_errmsg(errno),
						(errno == CONF_EROPENFAIL || errno == CONF_EROPENEMPTY) ? context->config_filename : "",
						", will keep your old configurations"
					);
					break;
				case CONF_ECPROXYDUP:
					config_log_duplicate_error(config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING, ", will keep your old configurations");
					break;
				default:
					mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
						"Error in processing configurations: Unknown error occurred, code: %d, will keep your old configurations\n",
						errno
					);
					break;
			}
	}
	if (generation_candidate != NULL) {
		if (result == 0 && hosts_prepared && hosts_candidate == NULL && !hosts_table_clone(route_generation_hosts(generation_candidate), &hosts_candidate)) {
			mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
				"Cannot preserve the candidate local static host table after route-generation activation failed.\n");
		}
		route_generation_release(generation_candidate);
		generation_candidate = NULL;
	}
	config_destroy(config_candidate);
	config_candidate = NULL;
	if (result == 0 && !primary_published && ((hosts_prepared && hosts_candidate != NULL) || read_status == CONF_READ_UNCHANGED)) {
		bool publish_hosts = hosts_prepared && hosts_candidate != NULL;
		if (!config_clone(context->config, &config_candidate)) {
			mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
				"Cannot clone the active configuration for a replacement route generation, keeping the existing generation.\n");
		} else if (hosts_candidate == NULL && !hosts_table_clone(context->hosts, &hosts_candidate)) {
			mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
				"Cannot clone the active local static host table for a replacement route generation, keeping the existing generation.\n");
		} else {
			if (read_status == CONF_READ_UNCHANGED) {
				config_icon_load(config_candidate, config_logfull_old, config_maxlevel, "keeping existing icon");
			}
			enum listener_route_prepare_status prepare_status = listener_generation_prepare(context, &config_candidate, &hosts_candidate, MKSYS_LEVEL_WARNING,
				", keeping the existing generation", &generation_candidate);
			if (prepare_status == LISTENER_ROUTE_PREPARE_TIME_ERROR) {
				mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_CRITICAL,
					"Cannot sample the monotonic clock while preparing local static host route resolution: %s\n", strerror(errno));
				result = -1;
			} else if (prepare_status == LISTENER_ROUTE_PREPARE_OK) {
				route_generation_registry_publish_status publish_status = listener_generation_publish(context, &generation_candidate);
				if (publish_status != ROUTE_GENERATION_REGISTRY_PUBLISH_OK) {
					mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_CRITICAL,
						"Cannot publish the replacement proxy route generation: %s.\n",
						publish_status == ROUTE_GENERATION_REGISTRY_PUBLISH_BLOCKED ? "a retired generation is still pinned" : "invalid internal generation state");
					result = -1;
				} else if (publish_hosts) {
					mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_INFORMATION, "Local static host table reloaded.\n");
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
		route_resolution_completion_status completion_status = route_generation_registry_completion_observe(context->generations, &completion, now);
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
		if (completion_status == ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT || waiter_invalid) {
			errno = EINVAL;
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

static int listener_worker_run(int client_fd, const listener_client_address *client_address, const uint8_t *inbound, size_t inbound_size,
	const connsetup_snapshot *snapshot, listener_socket *listener, const listener_events *events, pid_t listener_pid, listener_context *context) {
	close(events->epoll_fd);
	close(events->route_timer_fd);
	close(events->signal_fd);
	listener_socket_close(listener);
	listener_resolver_dispose_in_child(context);
	if (prctl(PR_SET_PDEATHSIG, SIGTERM) == -1) {
		mksysmsg(MKSYS_PREFIX_ON, snapshot->log_filename, snapshot->log_level, MKSYS_LEVEL_WARNING, "Cannot configure worker parent-death signal: %s\n", strerror(errno));
		listener_worker_route_state_dispose(context);
		return EXITCODE_INTERNAL;
	}
	if (getppid() != listener_pid) {
		listener_worker_route_state_dispose(context);
		return EXITCODE_OK;
	}
	if (listener_worker_signals_restore(&events->previous_signal_mask) == -1) {
		mksysmsg(MKSYS_PREFIX_ON, snapshot->log_filename, snapshot->log_level, MKSYS_LEVEL_WARNING, "Cannot restore worker signal state: %s\n", strerror(errno));
		listener_worker_route_state_dispose(context);
		return EXITCODE_INTERNAL;
	}
	listener_worker_route_state_dispose(context);
	net_addrbundle addrbundle_inbound_client = listener_client_address_parse(client_address);
	int socket_outbound;
	int setup_status = connsetup_prepared(client_fd, &socket_outbound, snapshot, addrbundle_inbound_client, inbound, inbound_size);
	if (setup_status == 0) {
		net_relay(client_fd, socket_outbound);
	}
	return EXITCODE_OK;
}

static void listener_connection_dispatch(listener_connection *connections, listener_connection *connection, listener_socket *listener, const listener_events *events,
	pid_t listener_pid, listener_context *context, const struct timespec *now) {
	connsetup_snapshot snapshot;
	if (!listener_connection_handoff_prepare(connection, context, now, &snapshot)) {
		LISTENER_LOG(context, MKSYS_LEVEL_WARNING, "Cannot prepare a self-contained worker handoff.\n");
		connection->closing = true;
		return;
	}
	int socket_flags = fcntl(connection->socket_fd, F_GETFL);
	if (socket_flags == -1 || fcntl(connection->socket_fd, F_SETFL, socket_flags & ~O_NONBLOCK) == -1) {
		LISTENER_LOG(context, MKSYS_LEVEL_WARNING, "Cannot prepare client connection for worker: %s\n", strerror(errno));
		connection->closing = true;
		return;
	}
	pid_t worker_pid = fork();
	if (worker_pid > 0) {
		connection->closing = true;
		return;
	}
	if (worker_pid < 0) {
		int saved_errno = errno;
		connection->closing = true;
		LISTENER_LOG(context, MKSYS_LEVEL_WARNING, "Cannot create worker process: %s\n", strerror(saved_errno));
		listener_backoff();
		return;
	}
	listener_connections_close_except(connections, connection);
	_exit(listener_worker_run(connection->socket_fd, &connection->address, connection->inbound, connection->inbound_size, &snapshot, listener, events, listener_pid, context));
}

static int listener_connections_route_progress(listener_connection *connections, listener_socket *listener, const listener_events *events, pid_t listener_pid,
	listener_context *context, const struct timespec *now) {
	for (listener_connection *connection = connections; connection != NULL; connection = connection->next) {
		if (connection->closing || connection->state != LISTENER_CONNECTION_ROUTE_WAITING) {
			continue;
		}
		enum listener_connection_progress progress = listener_connection_route_progress(connection, context->resolver, now);
		if (progress == LISTENER_CONNECTION_READY) {
			listener_connection_dispatch(connections, connection, listener, events, listener_pid, context, now);
		} else if (progress == LISTENER_CONNECTION_FATAL) {
			return -1;
		}
	}
	return 0;
}

static int listener_loop(listener_context *context, listener_socket *listener) {
	listener_events events;
	if (listener_events_init(&events) == -1) {
		LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot initialize listener event loop: %s\n", strerror(errno));
		listener_socket_close(listener);
		return EXITCODE_INTERNAL;
	}
	context->generations = route_generation_registry_create();
	if (context->generations == NULL) {
		LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot initialize proxy route generation ownership: memory allocation failed.\n");
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
		LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot initialize resolver runtime: %s\n", strerror(errno));
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
	enum listener_route_prepare_status resolution_status = listener_route_resolution_prepare(context, context->route_bindings, context->hosts, MKSYS_LEVEL_CRITICAL, "",
		&context->route_resolution);
	if (resolution_status != LISTENER_ROUTE_PREPARE_OK) {
		if (resolution_status == LISTENER_ROUTE_PREPARE_TIME_ERROR) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot sample the monotonic clock while preparing proxy route resolution: %s\n", strerror(errno));
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
		LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot publish the initial proxy route generation: invalid internal generation state.\n");
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
		LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot start proxy route prewarming: %s\n", strerror(errno));
		listener_resolver_destroy(context);
		listener_events_destroy(&events);
		listener_socket_close(listener);
		return EXITCODE_INTERNAL;
	}
	int exitcode = EXITCODE_OK;
	size_t connection_count = 0;
	const size_t connection_limit = listener_connection_limit();
	listener_connection *connections = NULL;
	pid_t listener_pid = getpid();
	bool reload_pending = false;
	bool shutting_down = false;
	while (1) {
		listener_requests requests;
		if (listener_events_wait(&events, &requests) == -1) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Listener event loop failed: %s\n", strerror(errno));
			exitcode = EXITCODE_INTERNAL;
			break;
		}
		if (requests.resolver_ready || requests.route_timer_ready) {
			if (clock_gettime(CLOCK_MONOTONIC, &route_now) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot sample the monotonic clock for route resolution: %s\n", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				break;
			}
			if (requests.resolver_ready && listener_resolver_events_process(context, connections, &route_now) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Resolver event processing failed: %s\n", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				break;
			}
			if (requests.route_timer_ready && listener_route_timer_drain(&events) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot consume the route warm-up timer: %s\n", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				break;
			}
		}
		if (requests.stop && !shutting_down) {
			if (listener_route_timer_set(&events, NULL) == -1 || listener_resolver_shutdown(context) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot shut down resolver runtime: %s\n", strerror(errno));
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
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Connection route resolution failed: %s\n", strerror(errno));
			exitcode = EXITCODE_INTERNAL;
			break;
		}
		route_generation_registry_collect(context->generations);
		bool reload_processed = false;
		if (route_runtime.ready && reload_pending && route_generation_registry_retired(context->generations) == NULL) {
			if (listener_notify_reloading() == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot create systemd reload timestamp: %s\n", strerror(errno));
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
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Proxy route prewarming failed: %s\n", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				break;
			}
		}
		if (route_runtime.ready && reload_pending && route_generation_registry_retired(context->generations) == NULL) {
			if (clock_gettime(CLOCK_MONOTONIC, &route_now) == -1 || listener_route_timer_set(&events, &route_now) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot resume a deferred configuration reload: %s\n", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				break;
			}
		}
		/* Consume socket data before timers from the same epoll batch, then reject only a still-current deadline. */
		for (int timeout_pass = 0; timeout_pass <= 1; timeout_pass++) {
			for (size_t ready_index = 0; ready_index < requests.ready_count; ready_index++) {
				const listener_event_source *source = requests.ready[ready_index].source;
				enum listener_event_kind kind = source->kind;
				if ((kind == LISTENER_EVENT_TIMEOUT) != (bool)timeout_pass) {
					continue;
				}
				listener_connection *connection = source->connection;
				if (connection == NULL || connection->closing) {
					continue;
				}
				enum listener_connection_progress progress = kind == LISTENER_EVENT_TIMEOUT
					? listener_connection_timeout(connection, requests.ready[ready_index].flags, requests.ready[ready_index].timer_generation, context->resolver, &route_now)
					: listener_connection_receive(connection, requests.ready[ready_index].flags);
				if (progress == LISTENER_CONNECTION_READY && connection->state == LISTENER_CONNECTION_INITIAL) {
					progress = listener_connection_route_start(connection, &events, context->resolver, &route_now);
				}
				if (progress == LISTENER_CONNECTION_READY) {
					listener_connection_dispatch(connections, connection, listener, &events, listener_pid, context, &route_now);
				} else if (progress == LISTENER_CONNECTION_FATAL) {
					LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Connection state processing failed: %s\n", strerror(errno));
					exitcode = EXITCODE_INTERNAL;
					goto cleanup;
				} else if (progress == LISTENER_CONNECTION_ABORT) {
					net_addrbundle client = listener_client_address_parse(&connection->address);
					LISTENER_LOG(context, MKSYS_LEVEL_WARNING, "src: %s:%d, status: abort_init\n", (char *)&client.address, client.port);
					connection->closing = true;
				}
			}
		}
		size_t destroyed_count = listener_connections_destroy_closed(&connections, &events, context->resolver, &route_now);
		if (destroyed_count > connection_count) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Listener connection accounting failed.\n");
			exitcode = EXITCODE_INTERNAL;
			break;
		}
		connection_count -= destroyed_count;
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
					LISTENER_LOG(context, MKSYS_LEVEL_WARNING, "Cannot accept client connection: %s\n", strerror(errno));
					listener_backoff();
					break;
				}
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot accept client connection: %s\n", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				goto cleanup;
			}
			if (connection_count >= connection_limit) {
				close(client_fd);
				continue;
			}
			route_generation *generation = route_generation_registry_active_retain(context->generations);
			if (generation == NULL) {
				close(client_fd);
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot retain the active route generation for a client connection.\n");
				exitcode = EXITCODE_INTERNAL;
				goto cleanup;
			}
			listener_connection *connection = listener_connection_create(client_fd, &client_address, &events, generation);
			if (connection == NULL) {
				int saved_errno = errno;
				LISTENER_LOG(context, MKSYS_LEVEL_WARNING, "Cannot track client connection: %s\n", strerror(saved_errno));
				listener_backoff();
				break;
			}
			connection->next = connections;
			connections = connection;
			connection_count++;
		}
	}
cleanup: {
	struct timespec cleanup_now;
	const struct timespec *cleanup_time = clock_gettime(CLOCK_MONOTONIC, &cleanup_now) == -1 ? NULL : &cleanup_now;
	while (connections != NULL) {
		listener_connection_destroy(&connections, connections, &events, context->resolver, cleanup_time);
	}
	listener_resolver_destroy(context);
	listener_events_destroy(&events);
	listener_socket_close(listener);
	return exitcode;
}
}

/* section: functions (exported) */
int listener_run(conf *config, conf_cache *config_cache, const char *config_filename, const char *config_filename_full, const char *working_directory, const char *log_filename) {
	listener_context context = {
		.config = config,
		.config_cache = config_cache,
		.config_filename = config_filename,
		.config_filename_full = config_filename_full,
		.generation_next_identity = 1,
		.working_directory = working_directory
	};
	snprintf(context.log_filename, sizeof(context.log_filename), "%s", log_filename);
	bool generation_owned;
	int exitcode;
	listener_socket listener = { .fd = -1 };
	enum listener_endpoint_status endpoint_status = listener_endpoint_prepare(context.config, &listener.endpoint);
	if (endpoint_status == LISTENER_ENDPOINT_BAD_ADDRESS) {
		LISTENER_LOG(&context, MKSYS_LEVEL_CRITICAL, "Error: Invalid bind address!\n");
		exitcode = EXITCODE_BINDFAIL;
		goto cleanup;
	}
	if (endpoint_status == LISTENER_ENDPOINT_BAD_PORT) {
		LISTENER_LOG(&context, MKSYS_LEVEL_CRITICAL, "Error: Invalid bind port!\n");
		exitcode = EXITCODE_BADPORT;
		goto cleanup;
	}
	route_table_build_status route_status = route_table_build(context.config, &context.routes);
	if (route_status != ROUTE_TABLE_BUILD_OK) {
		LISTENER_LOG(&context, MKSYS_LEVEL_CRITICAL, "Cannot prepare proxy routes: %s.\n",
			route_status == ROUTE_TABLE_BUILD_MEMORY ? "memory allocation failed" : "invalid internal route state");
		exitcode = EXITCODE_INTERNAL;
		goto cleanup;
	}
	net_addrp bindaddrp = net_ntop(listener.endpoint.address.family, &(listener.endpoint.address.addr), true);
	LISTENER_LOG(&context, MKSYS_LEVEL_INFORMATION, "Binding on %s:%d...\n", (char *)&bindaddrp, listener.endpoint.port);
	if (listener_socket_bind(&listener) == -1) {
		LISTENER_LOG(&context, MKSYS_LEVEL_CRITICAL, "Bind Failed!\n");
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
