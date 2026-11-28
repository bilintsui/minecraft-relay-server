/*
 * listener.c: Listener and worker process runtime
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
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
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <systemd/sd-daemon.h>
#include <time.h>
#include <unistd.h>

/* section: headers (project) */
#include "basic.h"
#include "config.h"
#include "connection/setup_long.h"
#include "define/exitcode.h"
#include "listener/connection.h"
#include "listener/events.h"
#include "listener/metrics.h"
#include "listener/short.h"
#include "listener/socket.h"
#if defined(LISTENER_EARLY_COLLECT_TEST) || defined(LISTENER_READY_FLIP_TEST) || defined(LISTENER_TIMER_REARM_TEST)
#include "listener_runtime_hooks.h"
#endif
#include "log.h"
#include "network.h"
#include "protocol/common.h"
#include "protocol/handshake.h"
#include "protocol/handshake_legacy.h"
#include "protocol/proxy.h"
#include "resolver/cache.h"
#include "resolver/hosts.h"
#include "resolver/hosts_watch.h"
#include "resolver/supervisor.h"
#include "route/bindings.h"
#include "route/generation.h"
#include "route/generation_registry.h"
#include "route/resolution.h"
#include "route/table.h"
#include "route/waiter.h"
#include "timeutil.h"
#include "version_info.h"

/* section: headers (self) */
#include "listener.h"

/* section: defines */
/* listener */
#ifndef LISTENER_ACCEPT_BATCH
#define LISTENER_ACCEPT_BATCH	128
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
#ifdef LISTENER_ROUTE_TIMER_ARMED_TEST
#define LISTENER_ROUTE_TIMER_ARMED_TEST_DELAY_SEC	60
#endif
#ifndef LISTENER_WORKER_LIMIT
#define LISTENER_WORKER_LIMIT	256
#endif
#ifndef LISTENER_WORKER_LOG_INTERVAL_SEC
#define LISTENER_WORKER_LOG_INTERVAL_SEC	10
#endif
#if LISTENER_WORKER_LIMIT < 1
#error "LISTENER_WORKER_LIMIT must be positive"
#endif

/* process names */
#define LISTENER_PROCESS_NAME	"mrs-listener"
#define LISTENER_WORKER_PROCESS_NAME	"worker"

/* logging macro */
#define LISTENER_LOG(ctx, lvl, ...)	MKSYS_LOG((ctx)->log_filename, (ctx)->config->log.level, lvl, __VA_ARGS__)
#define LISTENER_LOG_TERMINAL(ctx, lvl, ...)	MKSYS_LOG(MKSYS_NOLOGFILE, (ctx)->config->log.level, lvl, __VA_ARGS__)

/* section: types */
typedef enum {
	LISTENER_ROUTE_PREPARE_OK,
	LISTENER_ROUTE_PREPARE_CANDIDATE_ERROR,
	LISTENER_ROUTE_PREPARE_TIME_ERROR
} listener_route_prepare_status;
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
	listener_metrics_state metrics;
	listener_metrics_runtime metrics_runtime;
	resolver_supervisor *resolver;
	route_bindings *route_bindings;
	route_resolution *route_resolution;
	route_table *routes;
	const char *working_directory;
	listener_workers workers;
} listener_context;
typedef struct {
	struct timespec deadline;
	bool pressure_logged;
	bool ready;
} listener_route_runtime;

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
	mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, context->config->log.level, MKSYS_LEVEL_INFORMATION, MKSYS_PARAGRAPH_END, "For more information, see log file: %s", context->config->log.filename);
}

static const char *listener_protocol_label(proxy_prefix prefix) {
	switch (prefix) {
		case PROXY_PREFIX_OTHER:
			return "minecraft";
		case PROXY_PREFIX_V1:
			return "proxy_v1";
		case PROXY_PREFIX_V2:
			return "proxy_v2";
		default:
			return "unknown";
	}
}

static listener_connection_progress listener_protocol_mismatch(const listener_context *context, const listener_connection *connection, const char *received, proxy_prefix expected) {
	net_addrp peer = net_ntop(connection->peer_address.family, &connection->peer_address.addr, true);
	LISTENER_LOG(context, MKSYS_LEVEL_WARNING, "src: %s:%u, status: reject_invalid_protocol, received: %s, expected: %s", peer.v6, connection->peer_port, received, listener_protocol_label(expected));
	return LISTENER_CONNECTION_CLOSED;
}

static listener_connection_progress listener_proxy_exception(const listener_context *context, const net_addr *address, in_port_t port, const char *exception, int error) {
	net_addrp peer = net_ntop(address->family, &address->addr, true);
	LISTENER_LOG(context, MKSYS_LEVEL_WARNING, "peer: %s:%u, status: reject_proxy_exception, exception: %s%s%s", peer.v6, port, exception, error ? ", error: " : "", error ? strerror(error) : "");
	return LISTENER_CONNECTION_CLOSED;
}

static listener_connection_progress listener_connection_prefix(listener_connection *connection, const listener_context *context) {
	size_t consumed = 0;
	p_proxy *pair = &connection->inbound_proxy;
	if (connection->proxy_remaining == 0) {
		const conf *config = route_generation_config(connection->generation);
		proxy_prefix expected = config->listen.allow_proxy ? config->listen.proxy_version : PROXY_PREFIX_OTHER;
		proxy_prefix prefix = protocol_proxy_detect(connection->inbound, connection->inbound_size);
		if (prefix == PROXY_PREFIX_PARTIAL) {
			return LISTENER_CONNECTION_PENDING;
		}
		if (prefix != expected) {
			bool unknown = prefix == PROXY_PREFIX_OTHER && protocol_identify(connection->inbound, connection->inbound_size, NULL) == PVER_UNIDENT;
			return listener_protocol_mismatch(context, connection, unknown ? "unknown" : listener_protocol_label(prefix), expected);
		}
		if (prefix == PROXY_PREFIX_OTHER) {
			connection->prefix_checked = true;
			return LISTENER_CONNECTION_READY;
		}
		proxy_read_status status = prefix == PROXY_PREFIX_V2
			? protocol_proxy_v2_prefix_read(connection->inbound, connection->inbound_size, pair, &consumed, &connection->proxy_remaining)
			: protocol_proxy_read(connection->inbound, connection->inbound_size, pair, &consumed);
		if (status == PROXY_READ_INCOMPLETE) {
			return LISTENER_CONNECTION_PENDING;
		}
		if (status != PROXY_READ_COMPLETE) {
			return listener_proxy_exception(context, &connection->peer_address, connection->peer_port, status == PROXY_READ_TOO_LONG ? "header_too_long" : "malformed_header", 0);
		}
	}
	/* Reuse the assembly buffer for the opaque tail. Only bytes beyond its declared end belong to Minecraft. */
	size_t available = connection->inbound_size - consumed;
	if (available < connection->proxy_remaining) {
		connection->proxy_remaining -= (uint16_t)available;
		connection->inbound_size = 0;
		return LISTENER_CONNECTION_PENDING;
	}
	consumed += connection->proxy_remaining;
	connection->proxy_remaining = 0;
	connection->inbound_size -= consumed;
	memmove(connection->inbound, connection->inbound + consumed, connection->inbound_size);
	if (pair->family == AF_UNSPEC || connection->proxy_origin == CONNECTION_PROXY_UNTRUSTED_IGNORE) {
		if (pair->family == AF_UNSPEC && connection->proxy_origin == CONNECTION_PROXY_TRUSTED) {
			connection->proxy_origin = CONNECTION_PROXY_UNKNOWN;
		}
		if (!protocol_proxy_socket_read(connection->socket_fd, pair)) {
			return listener_proxy_exception(context, &connection->peer_address, connection->peer_port, "socket_endpoints_unavailable", errno);
		}
	}
	connection->prefix_checked = true;
	return LISTENER_CONNECTION_READY;
}

static listener_connection_progress listener_connection_receive(listener_connection *connection, uint32_t event_flags, const listener_context *context) {
	while (connection->inbound_size < sizeof(connection->inbound)) {
		ssize_t receive_size = recv(connection->socket_fd, connection->inbound + connection->inbound_size, sizeof(connection->inbound) - connection->inbound_size, 0);
		if (receive_size > 0) {
			connection->inbound_size += (size_t)receive_size;
			if (!connection->prefix_checked) {
				listener_connection_progress prefix = listener_connection_prefix(connection, context);
				if (prefix == LISTENER_CONNECTION_PENDING || (prefix == LISTENER_CONNECTION_READY && connection->inbound_size == 0)) {
					continue;
				}
				if (prefix != LISTENER_CONNECTION_READY) {
					return prefix;
				}
			}
			size_t packet_size;
			protocol_packet_status packet_status = protocol_packet_length(connection->inbound, connection->inbound_size, &packet_size);
			if (packet_status == PROTOCOL_PACKET_COMPLETE) {
				if (protocol_identify(connection->inbound, connection->inbound_size, NULL) != PVER_UNIDENT) {
					return LISTENER_CONNECTION_READY;
				}
				packet_status = PROTOCOL_PACKET_INVALID;
			}
			if (packet_status == PROTOCOL_PACKET_INVALID || packet_size > sizeof(connection->inbound)) {
				if (connection->proxy_origin == CONNECTION_PROXY_DIRECT && protocol_identify(connection->inbound, connection->inbound_size, NULL) == PVER_UNIDENT) {
					return listener_protocol_mismatch(context, connection, "unknown", PROXY_PREFIX_OTHER);
				}
				return LISTENER_CONNECTION_ABORT;
			}
			listener_connection_timer timer = packet_status == PROTOCOL_PACKET_AMBIGUOUS ? LISTENER_CONNECTION_TIMER_GRACE : LISTENER_CONNECTION_TIMER_ASSEMBLY;
			if (listener_connection_timer_arm(connection, timer) == -1) {
				return LISTENER_CONNECTION_ABORT;
			}
			continue;
		}
		bool header_pending = !connection->prefix_checked && connection->proxy_origin != CONNECTION_PROXY_DIRECT;
		if (receive_size == 0) {
			if (header_pending) {
				return listener_proxy_exception(context, &connection->peer_address, connection->peer_port, "header_eof", 0);
			}
			size_t packet_size;
			return protocol_packet_length(connection->inbound, connection->inbound_size, &packet_size) == PROTOCOL_PACKET_AMBIGUOUS
				&& protocol_identify(connection->inbound, connection->inbound_size, NULL) != PVER_UNIDENT ? LISTENER_CONNECTION_READY : LISTENER_CONNECTION_ABORT;
		}
		if (errno == EINTR) {
			continue;
		}
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if (!(event_flags & (EPOLLERR | EPOLLHUP | EPOLLRDHUP))) {
				return LISTENER_CONNECTION_PENDING;
			}
			return header_pending ? listener_proxy_exception(context, &connection->peer_address, connection->peer_port, "header_eof", 0) : LISTENER_CONNECTION_ABORT;
		}
		return header_pending ? listener_proxy_exception(context, &connection->peer_address, connection->peer_port, "read_error", errno) : LISTENER_CONNECTION_ABORT;
	}
	return LISTENER_CONNECTION_ABORT;
}

static bool listener_connection_route_cancelled(const listener_connection *connection, listener_event_kind kind, uint32_t event_flags) {
	return connection != NULL && connection->state == LISTENER_CONNECTION_ROUTE_WAITING && kind == LISTENER_EVENT_CLIENT && (event_flags & (EPOLLERR | EPOLLHUP | EPOLLRDHUP));
}

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

static listener_connection_progress listener_connection_route_progress(listener_connection *connection, listener_metrics_state *metrics, resolver_supervisor *supervisor, const struct timespec *now) {
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
				(void)listener_metrics_route_settle(metrics, &connection->route_metrics, LISTENER_METRICS_OUTCOME_INTERNAL_ERROR,
					LISTENER_METRICS_SELECTED_FAMILY_NONE, now);
				return LISTENER_CONNECTION_FATAL;
			}
			(void)listener_metrics_route_settle(metrics, &connection->route_metrics, LISTENER_METRICS_OUTCOME_READY,
				listener_connection_route_metrics_family(connection), now);
			return LISTENER_CONNECTION_READY;
		case ROUTE_WAITER_BAD_ARGUMENT:
			(void)listener_metrics_route_settle(metrics, &connection->route_metrics, LISTENER_METRICS_OUTCOME_INTERNAL_ERROR,
				LISTENER_METRICS_SELECTED_FAMILY_NONE, now);
			errno = EINVAL;
			return LISTENER_CONNECTION_FATAL;
		case ROUTE_WAITER_IO:
			(void)listener_metrics_route_settle(metrics, &connection->route_metrics, LISTENER_METRICS_OUTCOME_INTERNAL_ERROR,
				LISTENER_METRICS_SELECTED_FAMILY_NONE, now);
			errno = EIO;
			return LISTENER_CONNECTION_FATAL;
		case ROUTE_WAITER_TIME:
			(void)listener_metrics_route_settle(metrics, &connection->route_metrics, LISTENER_METRICS_OUTCOME_INTERNAL_ERROR,
				LISTENER_METRICS_SELECTED_FAMILY_NONE, now);
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
				LISTENER_METRICS_SELECTED_FAMILY_NONE, now);
			return LISTENER_CONNECTION_READY;
	}
}

static listener_connection_progress listener_connection_route_start(listener_connection *connection, const listener_events *events, listener_metrics_state *metrics,
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
			route == LISTENER_CONNECTION_ROUTE_SHORT_LOCAL ? LISTENER_METRICS_RESOLUTION_LOCAL : LISTENER_METRICS_RESOLUTION_BYPASS);
		(void)listener_metrics_route_settle(metrics, &connection->route_metrics,
			LISTENER_METRICS_OUTCOME_READY, LISTENER_METRICS_SELECTED_FAMILY_NONE, now);
		return LISTENER_CONNECTION_READY;
	}
	if (connection->inbound_proxy.family == AF_UNSPEC && !protocol_proxy_socket_read(connection->socket_fd, &connection->inbound_proxy)) {
		(void)listener_metrics_route_settle(metrics, &connection->route_metrics,
			LISTENER_METRICS_OUTCOME_INTERNAL_ERROR, LISTENER_METRICS_SELECTED_FAMILY_NONE, now);
		return LISTENER_CONNECTION_ABORT;
	}
	connection->state = LISTENER_CONNECTION_ROUTE_WAITING;
	route_waiter_create_status create_status = route_waiter_create(connection->generation, connection->vhost, &connection->inbound_proxy, now, &connection->waiter);
	if (create_status != ROUTE_WAITER_CREATE_OK) {
		if (create_status == ROUTE_WAITER_CREATE_BAD_ARGUMENT || create_status == ROUTE_WAITER_CREATE_TIME) {
			(void)listener_metrics_route_settle(metrics, &connection->route_metrics,
				LISTENER_METRICS_OUTCOME_INTERNAL_ERROR, LISTENER_METRICS_SELECTED_FAMILY_NONE, now);
			errno = create_status == ROUTE_WAITER_CREATE_TIME ? EOVERFLOW : EINVAL;
			return LISTENER_CONNECTION_FATAL;
		}
		connection->waiter_status = create_status == ROUTE_WAITER_CREATE_LIMIT ? ROUTE_WAITER_LIMIT : ROUTE_WAITER_MEMORY;
		(void)listener_metrics_route_settle(metrics, &connection->route_metrics,
			create_status == ROUTE_WAITER_CREATE_LIMIT ? LISTENER_METRICS_OUTCOME_LIMIT : LISTENER_METRICS_OUTCOME_MEMORY,
			LISTENER_METRICS_SELECTED_FAMILY_NONE, now);
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
			LISTENER_METRICS_RESOLUTION_WAITED);
		(void)listener_metrics_route_settle(metrics, &connection->route_metrics,
			LISTENER_METRICS_OUTCOME_INTERNAL_ERROR, LISTENER_METRICS_SELECTED_FAMILY_NONE, now);
		return LISTENER_CONNECTION_FATAL;
	}
	return LISTENER_CONNECTION_PENDING;
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
	if (!connection->prefix_checked && connection->proxy_origin != CONNECTION_PROXY_DIRECT) {
		return listener_proxy_exception(context, &connection->peer_address, connection->peer_port, "header_timeout", 0);
	}
	return connection->timer == LISTENER_CONNECTION_TIMER_GRACE && protocol_identify(connection->inbound, connection->inbound_size, NULL) != PVER_UNIDENT
		? LISTENER_CONNECTION_READY : LISTENER_CONNECTION_ABORT;
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
		errno = EINVAL;
		return ROUTE_GENERATION_REGISTRY_PUBLISH_BAD_ARGUMENT;
	}
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
		return ROUTE_GENERATION_REGISTRY_PUBLISH_TIME;
	}
	route_generation_registry_publish_status status = route_generation_registry_publish(context->generations, candidate, context->resolver, &now);
	if (*candidate != NULL) {
		if (status == ROUTE_GENERATION_REGISTRY_PUBLISH_BAD_ARGUMENT) {
			errno = EINVAL;
		} else if (status == ROUTE_GENERATION_REGISTRY_PUBLISH_IO) {
			errno = EIO;
		} else if (status == ROUTE_GENERATION_REGISTRY_PUBLISH_TIME) {
			errno = EOVERFLOW;
		}
		return status;
	}
	route_generation *active = route_generation_registry_active(context->generations);
	if (active == NULL) {
		errno = EINVAL;
		return ROUTE_GENERATION_REGISTRY_PUBLISH_BAD_ARGUMENT;
	}
	context->config = (conf *)route_generation_config(active);
	context->hosts = (hosts_table *)route_generation_hosts(active);
	context->route_bindings = (route_bindings *)route_generation_bindings(active);
	context->route_resolution = route_generation_resolution(active);
	context->routes = (route_table *)route_generation_routes(active);
	context->generation_next_identity = context->generation_next_identity == UINT64_MAX ? 0 : context->generation_next_identity + 1U;
	if (status != ROUTE_GENERATION_REGISTRY_PUBLISH_OK) {
		errno = status == ROUTE_GENERATION_REGISTRY_PUBLISH_IO ? EIO : status == ROUTE_GENERATION_REGISTRY_PUBLISH_TIME ? EOVERFLOW : EINVAL;
	}
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
		LISTENER_LOG(context, failure_level,
			"Cannot prepare local static host table from %s: %s%s.",
			LISTENER_HOSTS_FILENAME, listener_hosts_load_error(status), failure_action
		);
		return false;
	}
	if (*result == NULL) {
		LISTENER_LOG(context, failure_level,
			"Cannot prepare local static host table from %s: loader returned no table%s.",
			LISTENER_HOSTS_FILENAME, failure_action
		);
		return false;
	}
	if (status == HOSTS_LOAD_FILE_ERROR) {
		LISTENER_LOG(context, MKSYS_LEVEL_WARNING,
			"Cannot read local static host table from %s; using guaranteed localhost entries.",
			LISTENER_HOSTS_FILENAME
		);
	}
	if (malformed_line_count > 0) {
		LISTENER_LOG(context, MKSYS_LEVEL_WARNING,
			"Ignored %zu malformed line%s while loading local static host table from %s.",
			malformed_line_count, malformed_line_count == 1 ? "" : "s", LISTENER_HOSTS_FILENAME
		);
	}
	return true;
}

static bool listener_hosts_watch_process(listener_context *context, listener_events *events, bool failed, bool ready) {
	bool changed = failed;
	bool refresh = failed;
	if (ready) {
		hosts_watch_events watch_events;
		hosts_watch_read_status status = listener_events_hosts_watch_read(events, &watch_events);
		if (status == HOSTS_WATCH_READ_OK) {
			changed = changed || watch_events.changed;
			refresh = refresh || watch_events.refresh;
		} else {
			int saved_errno = errno;
			changed = true;
			refresh = true;
			LISTENER_LOG(context, MKSYS_LEVEL_WARNING,
				"Cannot consume local static host table monitor events: %s; the latest table will still be reloaded.",
				strerror(saved_errno)
			);
		}
	}
	if (refresh) {
		bool overlap_changed = false;
		int status = listener_events_hosts_watch_establish(events, LISTENER_HOSTS_FILENAME, &overlap_changed);
		if (status == -1) {
			int saved_errno = errno;
			listener_events_hosts_watch_disable(events);
			LISTENER_LOG(context, MKSYS_LEVEL_WARNING,
				"Cannot refresh automatic monitoring for local static host table %s: %s; SIGUSR1 reload remains available.",
				LISTENER_HOSTS_FILENAME, strerror(saved_errno)
			);
		} else if (status == 1) {
			LISTENER_LOG(context, MKSYS_LEVEL_INFORMATION,
				"Automatic monitoring for local static host table %s restored.",
				LISTENER_HOSTS_FILENAME
			);
		}
		changed = changed || overlap_changed;
	}
	return changed;
}

static void listener_hosts_watch_retry(listener_context *context, listener_events *events) {
	int status = listener_events_hosts_watch_establish(events, LISTENER_HOSTS_FILENAME, NULL);
	if (status == -1) {
		int saved_errno = errno;
		LISTENER_LOG(context, MKSYS_LEVEL_WARNING,
			"Cannot monitor local static host table %s automatically: %s; SIGUSR1 reload remains available.",
			LISTENER_HOSTS_FILENAME, strerror(saved_errno)
		);
	} else if (status == 1) {
		LISTENER_LOG(context, MKSYS_LEVEL_INFORMATION,
			"Automatic monitoring for local static host table %s restored.",
			LISTENER_HOSTS_FILENAME
		);
	}
}

static bool listener_metrics_aggregate_snapshot_get(const listener_context *context, listener_metrics_aggregate_snapshot *snapshot) {
	return context != NULL && snapshot != NULL && listener_metrics_snapshot_get(&context->metrics, &snapshot->listener)
		&& resolver_cache_metrics_get(context->dns_cache, &snapshot->cache)
		&& resolver_supervisor_metrics_assembly_get(context->resolver, &snapshot->assembly)
		&& resolver_supervisor_metrics_get(context->resolver, &snapshot->supervisor);
}

static void listener_metrics_observations_drain(listener_context *context, const struct timespec *now) {
	if (context == NULL || context->resolver == NULL || !timeutil_valid(now)) {
		return;
	}
	resolver_supervisor_observation observation;
	while (resolver_supervisor_observation_take(context->resolver, &observation)) {
		listener_metrics_helper_observation_log(&context->metrics_runtime, &observation, context->log_filename, context->config->log.level, now);
	}
	listener_metrics_helper_observation_loss_log(&context->metrics_runtime, resolver_supervisor_observation_dropped(context->resolver), context->log_filename, context->config->log.level, now);
}

static void listener_metrics_snapshot_output(listener_context *context, listener_metrics_output_reason reason, const char *log_filename, uint8_t log_level, const struct timespec *now) {
	int saved_errno = errno;
	listener_metrics_aggregate_snapshot snapshot;
	if (listener_metrics_aggregate_snapshot_get(context, &snapshot)) {
		listener_metrics_output(&context->metrics_runtime, reason, &snapshot, log_filename, log_level, now);
	} else {
		listener_metrics_format_drop_record(&context->metrics_runtime);
	}
	errno = saved_errno;
}

static void listener_metrics_timer_failure(listener_context *context, int failure_errno, const char *log_filename, uint8_t log_level) {
	listener_metrics_scheduler_failure_record(&context->metrics_runtime);
	MKSYS_LOG(log_filename, log_level, MKSYS_LEVEL_WARNING, "Metrics timer disabled after an observation-subsystem failure: %s", strerror(failure_errno));
}

static listener_metrics_timer_read_status listener_metrics_timer_read(listener_context *context, listener_events *events, bool event_failed, uint64_t *expirations) {
	int saved_errno = errno;
	listener_metrics_timer_read_status status = listener_events_metrics_timer_read(events, event_failed, expirations);
	if (status == LISTENER_METRICS_TIMER_FAILED) {
		listener_metrics_timer_failure(context, errno, context->log_filename, context->config->log.level);
	}
	errno = saved_errno;
	return status;
}

static void listener_metrics_timer_set(listener_context *context, listener_events *events, uint32_t interval, const char *log_filename, uint8_t log_level) {
	int saved_errno = errno;
	if (listener_events_metrics_timer_set(events, interval) == -1) {
		listener_metrics_timer_failure(context, errno, log_filename, log_level);
	}
	errno = saved_errno;
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

static int listener_hosts_reload(listener_context *context) {
	conf *config_candidate = NULL;
	hosts_table *hosts_candidate = NULL;
	route_generation *generation_candidate = NULL;
	int result = 0;
	if (!listener_hosts_prepare(context, MKSYS_LEVEL_WARNING, ", keeping the existing table", &hosts_candidate)) {
		return 0;
	}
	if (!config_clone(context->config, &config_candidate)) {
		LISTENER_LOG(context, MKSYS_LEVEL_WARNING,
			"Cannot clone the active configuration for an automatic local static host table reload, keeping the existing generation."
		);
		goto cleanup;
	}
	listener_route_prepare_status prepare_status = listener_generation_prepare(context, &config_candidate, &hosts_candidate, MKSYS_LEVEL_WARNING,
		", keeping the existing generation", &generation_candidate);
	if (prepare_status == LISTENER_ROUTE_PREPARE_TIME_ERROR) {
		LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
			"Cannot sample the monotonic clock while preparing automatic local static host route resolution: %s",
			strerror(errno)
		);
		result = -1;
		goto cleanup;
	}
	if (prepare_status != LISTENER_ROUTE_PREPARE_OK) {
		goto cleanup;
	}
	route_generation_registry_publish_status publish_status = listener_generation_publish(context, &generation_candidate);
	if (publish_status != ROUTE_GENERATION_REGISTRY_PUBLISH_OK) {
		LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
			"Cannot publish the automatically reloaded local static host route generation: %s.",
			publish_status == ROUTE_GENERATION_REGISTRY_PUBLISH_BLOCKED ? "a retired generation is still pinned" : strerror(errno)
		);
		result = -1;
		goto cleanup;
	}
	LISTENER_LOG(context, MKSYS_LEVEL_INFORMATION,
		"Local static host table reloaded automatically."
	);

cleanup:
	config_destroy(config_candidate);
	hosts_table_destroy(hosts_candidate);
	route_generation_release(generation_candidate);
	return result;
}

#ifdef LISTENER_ROUTE_TIMER_ARMED_TEST
static int listener_route_timer_armed_test_apply(struct itimerspec *timer) {
	if (getenv("MCRELAY_TEST_ROUTE_TIMER_ARMED") == NULL) {
		return 0;
	}
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
		return -1;
	}
	if (!timeutil_add_seconds(&now, LISTENER_ROUTE_TIMER_ARMED_TEST_DELAY_SEC, &timer->it_value)) {
		errno = EOVERFLOW;
		return -1;
	}
	return 1;
}

static int listener_route_timer_armed_test_notify(void) {
	static bool notified;
	if (notified) {
		return 0;
	}
	int result = sd_notify(0, "MCRELAY_TEST_ROUTE_TIMER_ARMED=1");
	if (result < 0) {
		errno = -result;
		return -1;
	}
	notified = true;
	return 0;
}
#endif

static int listener_route_timer_set(const listener_events *events, const struct timespec *deadline) {
	struct itimerspec timer;
	memset(&timer, 0, sizeof(timer));
	if (deadline != NULL) {
		timer.it_value = *deadline;
	}
#ifdef LISTENER_ROUTE_TIMER_ARMED_TEST
	int armed_test = deadline == NULL ? listener_route_timer_armed_test_apply(&timer) : 0;
	if (armed_test == -1) {
		return -1;
	}
#endif
	if (listener_events_route_timer_set(events, &timer) == -1) {
		return -1;
	}
#ifdef LISTENER_ROUTE_TIMER_ARMED_TEST
	if (armed_test == 1 && listener_route_timer_armed_test_notify() == -1) {
		return -1;
	}
#endif
	return 0;
}

#ifdef LISTENER_READY_FLIP_TEST
static int listener_ready_flip_test_timer_disarm(const void *context) {
	return listener_route_timer_set(context, NULL);
}
#endif

static int listener_route_runtime_ready(listener_context *context, listener_route_runtime *runtime, listener_events *events, const listener_socket *listener, bool warmup_complete, const struct timespec *now) {
	if (listener_events_socket_add(events, listener->fd) == -1) {
		return -1;
	}
	runtime->ready = true;
	listener_notify_ready();
	if (!isatty(STDOUT_FILENO)) {
		fflush(stdout);
		fflush(stderr);
		int null_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
		if (null_fd != -1) {
			dup2(null_fd, STDOUT_FILENO);
			if (dup2(null_fd, STDERR_FILENO) != -1) {
				log_stderr_prepare();
			}
			if (null_fd != STDOUT_FILENO && null_fd != STDERR_FILENO) {
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
	if (listener_metrics_effectively_enabled(context->config)) {
		listener_metrics_timer_set(context, events, context->config->metrics.interval, context->log_filename, context->config->log.level);
		listener_metrics_snapshot_output(context, LISTENER_METRICS_OUTPUT_STARTUP, context->log_filename, context->config->log.level, now);
	}
	return 0;
}

static int listener_route_runtime_schedule(listener_context *context, listener_route_runtime *runtime, listener_events *events, const listener_socket *listener, const struct timespec *now) {
	route_prewarm_status status = route_resolution_schedule(context->route_resolution, context->resolver, now, LISTENER_ROUTE_PREWARM_BATCH_LIMIT);
	if (status == ROUTE_PREWARM_BAD_ARGUMENT || status == ROUTE_PREWARM_IO || status == ROUTE_PREWARM_TIME) {
		errno = status == ROUTE_PREWARM_TIME ? EOVERFLOW : status == ROUTE_PREWARM_IO ? EIO : EINVAL;
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
		LISTENER_LOG(context, MKSYS_LEVEL_INFORMATION,
			"Proxy route prewarming resumed after local resolver pressure."
		);
		runtime->pressure_logged = false;
	}
	bool deadline_reached = timeutil_compare(now, &runtime->deadline) >= 0;
	bool warmup_complete = route_resolution_warmup_complete(context->route_resolution);
#ifdef LISTENER_READY_FLIP_TEST
	int ready_flip_hold = listener_test_ready_flip_hold(runtime->ready, warmup_complete, listener_ready_flip_test_timer_disarm, events);
	if (ready_flip_hold == -1) {
		return -1;
	}
	if (ready_flip_hold == 1) {
		return 0;
	}
#endif
	if (!runtime->ready && (warmup_complete || deadline_reached) && listener_route_runtime_ready(context, runtime, events, listener, warmup_complete, now) == -1) {
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
	if (LISTENER_ROUTE_PREWARM_BATCH_LIMIT == 0 || LISTENER_ROUTE_WARMUP_TIMEOUT_SEC == 0 || !timeutil_add_seconds(now, LISTENER_ROUTE_WARMUP_TIMEOUT_SEC, &runtime->deadline)) {
		errno = EINVAL;
		return -1;
	}
	return listener_route_timer_set(events, &runtime->deadline);
}

static int listener_reload(listener_context *context, listener_socket *listener, listener_events *events, bool *metrics_readiness_invalidated) {
	uint8_t config_maxlevel = context->config->log.level;
	bool metrics_effective_old = listener_metrics_effectively_enabled(context->config);
	uint32_t metrics_interval_old = context->config->metrics.interval;
	int result = 0;
	*metrics_readiness_invalidated = false;
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
	conf_read_status read_status = config_read_with_log(context->config_filename_full, context->config_cache, &config_cache_candidate, &config_candidate, config_logfull_old, config_maxlevel);
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
					publish_status == ROUTE_GENERATION_REGISTRY_PUBLISH_BLOCKED ? "a retired generation is still pinned" : strerror(errno)
				);
				result = -1;
				break;
			}
			bool metrics_effective_new = listener_metrics_effectively_enabled(context->config);
			bool metrics_transition = metrics_effective_old != metrics_effective_new
				|| (metrics_effective_new && metrics_interval_old != context->config->metrics.interval);
			*metrics_readiness_invalidated = metrics_transition;
			if (metrics_effective_old && !metrics_effective_new) {
				struct timespec metrics_now;
				if (clock_gettime(CLOCK_MONOTONIC, &metrics_now) == 0) {
					listener_metrics_snapshot_output(context, LISTENER_METRICS_OUTPUT_DISABLE, config_logfull_old, config_maxlevel, &metrics_now);
				} else {
					listener_metrics_format_drop_record(&context->metrics_runtime);
				}
				listener_metrics_timer_set(context, events, 0, config_logfull_old, config_maxlevel);
			}
			snprintf(context->log_filename, sizeof(context->log_filename), "%s", config_logfull_candidate);
			config_cache_commit(context->config_cache, &config_cache_candidate);
			primary_published = true;
			if (metrics_effective_new && metrics_transition) {
				listener_metrics_timer_set(context, events, context->config->metrics.interval, context->log_filename, context->config->log.level);
				struct timespec metrics_now;
				if (clock_gettime(CLOCK_MONOTONIC, &metrics_now) == 0) {
					listener_metrics_snapshot_output(context, LISTENER_METRICS_OUTPUT_RECONFIGURE, context->log_filename, context->config->log.level, &metrics_now);
				} else {
					listener_metrics_format_drop_record(&context->metrics_runtime);
				}
			} else if (metrics_effective_new && listener_events_metrics_timer_needs_retry(events)) {
				listener_metrics_timer_set(context, events, context->config->metrics.interval, context->log_filename, context->config->log.level);
			}
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
				case CONF_ECFIELD:
					/* The field diagnostic was written to the active log during validation. */
					break;
				case CONF_EROPENFAIL:
				case CONF_EROPENEMPTY:
				case CONF_EROPENLARGE:
				case CONF_ERMEMORY:
				case CONF_ERPARSE:
				case CONF_ECMEMORY:
				case CONF_ECLISTENPORT:
				case CONF_ECMETRICS:
				case CONF_ECPROXY:
					MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
						"%s%s%s",
						config_errmsg((conf_error)errno),
						(errno == CONF_EROPENFAIL || errno == CONF_EROPENEMPTY) ? context->config_filename : "", ", will keep your old configurations"
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
						publish_status == ROUTE_GENERATION_REGISTRY_PUBLISH_BLOCKED ? "a retired generation is still pinned" : strerror(errno)
					);
					result = -1;
				} else if (publish_hosts) {
					MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_INFORMATION,
						"Local static host table reloaded."
					);
				}
			}
		}
	}
	if (result == 0 && read_status == CONF_READ_UNCHANGED && metrics_effective_old && listener_events_metrics_timer_needs_retry(events)) {
		listener_metrics_timer_set(context, events, metrics_interval_old, config_logfull_old, config_maxlevel);
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
		errno = status == RESOLVER_SUPERVISOR_EVENT_TIME ? EOVERFLOW : status == RESOLVER_SUPERVISOR_EVENT_IO ? EIO : EINVAL;
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
	if (workers->refusal_logged && timeutil_add_seconds(&workers->refusal_logged_at, LISTENER_WORKER_LOG_INTERVAL_SEC, &next_log) && timeutil_compare(&now, &next_log) < 0) {
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

static exit_code listener_worker_run(int client_fd, net_addrbundle client, const uint8_t *inbound, size_t inbound_size,
	const connection_setup_snapshot *snapshot, listener_socket *listener, listener_events *events, pid_t listener_pid, listener_context *context) {
	if (prctl(PR_SET_NAME, LISTENER_WORKER_PROCESS_NAME) == -1) {
		CONNECTION_SETUP_LOG(snapshot, MKSYS_LEVEL_WARNING, "Cannot set worker process name: %s", strerror(errno));
	}
	listener_events_dispose_in_child(events);
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
	uint8_t seed[CONNECTION_SETUP_LONG_PENDING_MAX];
	size_t seed_size;
	int socket_outbound;
	connection_setup_status setup_status = connection_setup_long_prepared(client_fd, &socket_outbound, snapshot, client, inbound, inbound_size, seed, &seed_size);
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

static listener_connection_progress listener_connection_dispatch(listener_connection *connections, listener_connection *connection, listener_socket *listener, listener_events *events,
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

static listener_connection_progress listener_connection_ready(listener_connection *connections, listener_connection *connection, listener_socket *listener,
	listener_events *events, pid_t listener_pid, listener_context *context, const struct timespec *now) {
	if (connection->dispatch == LISTENER_CONNECTION_ROUTE_SHORT_LOCAL || connection->dispatch == LISTENER_CONNECTION_ROUTE_SHORT_WAIT) {
		return listener_short_start(connection, events, context->working_directory, &context->metrics, context->resolver, now);
	}
	if (connection->dispatch == LISTENER_CONNECTION_ROUTE_WORKER_BYPASS || connection->dispatch == LISTENER_CONNECTION_ROUTE_WORKER_WAIT) {
		return listener_connection_dispatch(connections, connection, listener, events, listener_pid, context, now);
	}
	return LISTENER_CONNECTION_ABORT;
}

static int listener_connections_route_progress(listener_connection *connections, listener_socket *listener, listener_events *events, pid_t listener_pid,
	listener_context *context, const struct timespec *now) {
	for (listener_connection *connection = connections; connection != NULL; connection = connection->next) {
		if (connection->closing || connection->state != LISTENER_CONNECTION_ROUTE_WAITING) {
			continue;
		}
		listener_connection_progress progress = listener_connection_route_progress(connection, &context->metrics, context->resolver, now);
		if (progress == LISTENER_CONNECTION_READY) {
			progress = listener_connection_ready(connections, connection, listener, events, listener_pid, context, now);
		}
		if (progress == LISTENER_CONNECTION_FATAL) {
			return -1;
		}
		listener_connection_finish(connection, progress, context->log_filename, context->config->log.level);
	}
	return 0;
}

static exit_code listener_loop(listener_context *context, listener_socket *listener) {
	listener_events events;
	if (listener_events_init(&events) == -1) {
		LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
			"Cannot initialize listener event loop: %s",
			strerror(errno)
		);
		listener_socket_close(listener);
		return EXITCODE_INTERNAL;
	}
	listener_hosts_watch_retry(context, &events);
	context->generations = route_generation_registry_create();
	if (context->generations == NULL) {
		LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
			"Cannot initialize proxy route generation ownership: memory allocation failed."
		);
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
		LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
			"Cannot initialize resolver runtime: %s",
			strerror(errno)
		);
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
	listener_route_prepare_status resolution_status = listener_route_resolution_prepare(context, context->route_bindings, context->hosts, MKSYS_LEVEL_CRITICAL, "", &context->route_resolution);
	if (resolution_status != LISTENER_ROUTE_PREPARE_OK) {
		if (resolution_status == LISTENER_ROUTE_PREPARE_TIME_ERROR) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
				"Cannot sample the monotonic clock while preparing proxy route resolution: %s",
				strerror(errno)
			);
		}
		listener_resolver_destroy(context);
		listener_events_destroy(&events);
		listener_socket_close(listener);
		return EXITCODE_INTERNAL;
	}
	route_generation *initial_generation = NULL;
	if (!listener_generation_create(context, context->config, context->hosts, context->routes, context->route_bindings, context->route_resolution, MKSYS_LEVEL_CRITICAL, "", &initial_generation)) {
		listener_resolver_destroy(context);
		listener_events_destroy(&events);
		listener_socket_close(listener);
		return EXITCODE_INTERNAL;
	}
	route_generation_registry_publish_status initial_publish_status = listener_generation_publish(context, &initial_generation);
	if (initial_publish_status != ROUTE_GENERATION_REGISTRY_PUBLISH_OK) {
		LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
			"Cannot publish the initial proxy route generation: %s.",
			initial_publish_status == ROUTE_GENERATION_REGISTRY_PUBLISH_BLOCKED ? "a retired generation is still pinned" : strerror(errno)
		);
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
	const size_t connection_limit = listener_connection_limit();
	listener_metrics_limits_set(&context->metrics, connection_limit, LISTENER_WORKER_LIMIT);
	listener_bind_success_msg(context);
	struct timespec route_now;
	listener_route_runtime route_runtime;
	pid_t listener_pid = getpid();
	if (clock_gettime(CLOCK_MONOTONIC, &route_now) == -1 || !listener_metrics_runtime_init(&context->metrics_runtime, listener_pid, &route_now)
		|| listener_route_runtime_start(&route_runtime, &events, &route_now) == -1
		|| listener_route_runtime_schedule(context, &route_runtime, &events, listener, &route_now) == -1) {
		LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot start proxy route prewarming: %s", strerror(errno));
		listener_resolver_destroy(context);
		listener_events_destroy(&events);
		listener_socket_close(listener);
		return EXITCODE_INTERNAL;
	}
	exit_code exitcode = EXITCODE_OK;
	size_t connection_count = 0;
	listener_connection *connections = NULL;
	bool hosts_reload_pending = false;
	bool reload_pending = false;
	bool shutting_down = false;
	while (1) {
		listener_requests requests;
		if (listener_events_wait(&events, &requests) == -1) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
				"Listener event loop failed: %s",
				strerror(errno)
			);
			exitcode = EXITCODE_INTERNAL;
			break;
		}
		if (requests.hosts_watch_failed || requests.hosts_watch_ready) {
			hosts_reload_pending = listener_hosts_watch_process(context, &events, requests.hosts_watch_failed, requests.hosts_watch_ready) || hosts_reload_pending;
		}
		/* Client cancellation wins when route completion and peer shutdown are ready in the same epoll batch. */
		for (size_t ready_index = 0; ready_index < requests.ready_count; ready_index++) {
			const listener_ready_event *ready = &requests.ready[ready_index];
			if (listener_connection_route_cancelled(ready->source->connection, ready->source->kind, ready->flags)) {
				ready->source->connection->closing = true;
			}
		}
		/* Release connection interests and enter supervisor shutdown before processing helper exits from the same stop batch. */
		if ((!requests.stop || shutting_down) && (requests.resolver_ready || requests.route_timer_ready)) {
			if (clock_gettime(CLOCK_MONOTONIC, &route_now) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
					"Cannot sample the monotonic clock for route resolution: %s",
					strerror(errno)
				);
				exitcode = EXITCODE_INTERNAL;
				break;
			}
			if (requests.resolver_ready && listener_resolver_events_process(context, connections, &route_now) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
					"Resolver event processing failed: %s",
					strerror(errno)
				);
				exitcode = EXITCODE_INTERNAL;
				break;
			}
			if (requests.route_timer_ready && listener_events_route_timer_drain(&events) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
					"Cannot consume the route warm-up timer: %s",
					strerror(errno)
				);
				exitcode = EXITCODE_INTERNAL;
				break;
			}
#ifdef LISTENER_READY_FLIP_TEST
			if (requests.route_timer_ready && listener_test_ready_flip_timer_event() == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
					"Cannot notify the ready-flip timer test: %s",
					strerror(errno)
				);
				exitcode = EXITCODE_INTERNAL;
				break;
			}
#endif
		}
		if (requests.child_ready && listener_workers_reap(context) == -1) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
				"Cannot reap a worker process: %s",
				strerror(errno)
			);
			exitcode = EXITCODE_INTERNAL;
			break;
		}
		if (requests.stop && !shutting_down) {
			resolver_supervisor_shutdown_prepare(context->resolver);
			listener_metrics_timer_set(context, &events, 0, context->log_filename, context->config->log.level);
			if (clock_gettime(CLOCK_MONOTONIC, &route_now) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
					"Cannot sample the monotonic clock while closing listener connections: %s",
					strerror(errno)
				);
				exitcode = EXITCODE_INTERNAL;
				break;
			}
			int connection_destroy_errno = 0;
			while (connections != NULL) {
				if (!listener_connection_destroy(&connections, connections, &events, &context->metrics, LISTENER_METRICS_OUTCOME_SHUTDOWN, context->resolver, &route_now)
					&& connection_destroy_errno == 0) {
					connection_destroy_errno = errno;
				}
			}
			connection_count = 0;
			if (connection_destroy_errno != 0) {
				errno = connection_destroy_errno;
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
					"Cannot release connection route interests during shutdown: %s",
					strerror(errno)
				);
				exitcode = EXITCODE_INTERNAL;
				break;
			}
			if (listener_route_timer_set(&events, NULL) == -1 || listener_resolver_shutdown(context) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
					"Cannot shut down resolver runtime: %s",
					strerror(errno)
				);
				exitcode = EXITCODE_INTERNAL;
				break;
			}
			shutting_down = true;
		}
		if (shutting_down) {
			struct timespec metrics_now = { 0 };
			bool metrics_time_valid = clock_gettime(CLOCK_MONOTONIC, &metrics_now) == 0;
			if (metrics_time_valid) {
				listener_metrics_observations_drain(context, &metrics_now);
			}
			if (resolver_supervisor_shutdown_complete(context->resolver)) {
				if (listener_metrics_effectively_enabled(context->config) && metrics_time_valid) {
					listener_metrics_snapshot_output(context, LISTENER_METRICS_OUTPUT_SHUTDOWN, context->log_filename, context->config->log.level, &metrics_now);
				}
				break;
			}
			continue;
		}
		if (requests.reload) {
			reload_pending = true;
#ifdef LISTENER_READY_FLIP_TEST
			if (listener_test_ready_flip_release() == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
					"Cannot notify the ready-flip reload test: %s",
					strerror(errno)
				);
				exitcode = EXITCODE_INTERNAL;
				break;
			}
#endif
#ifdef LISTENER_EARLY_COLLECT_TEST
			if (listener_test_early_collect_reload_ack() == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
					"Cannot notify the early-collect reload test: %s",
					strerror(errno)
				);
				exitcode = EXITCODE_INTERNAL;
				break;
			}
#endif
		}
		if (requests.resolver_ready && listener_connections_route_progress(connections, listener, &events, listener_pid, context, &route_now) == -1) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
				"Connection route resolution failed: %s",
				strerror(errno)
			);
			exitcode = EXITCODE_INTERNAL;
			break;
		}
#ifdef LISTENER_EARLY_COLLECT_TEST
		bool retired_before_collect = route_generation_registry_retired(context->generations) != NULL;
#endif
		if (!listener_generation_collect(context, &route_now)) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
				"Cannot collect a retired proxy route generation: %s",
				strerror(errno)
			);
			exitcode = EXITCODE_INTERNAL;
			break;
		}
		bool reload_processed = false;
		bool metrics_readiness_invalidated = false;
#ifdef LISTENER_READY_FLIP_TEST
		/* Exclude unrelated test-daemon events: this scenario may reload only after the late-arm timer actually fires. */
		bool ready_flip_timer_ready = listener_test_ready_flip_timer_ready();
		if (!route_runtime.ready && reload_pending) {
			if (listener_test_ready_flip_reload_blocked() == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
					"Cannot notify the ready-flip reload test: %s",
					strerror(errno)
				);
				exitcode = EXITCODE_INTERNAL;
				break;
			}
		}
#endif
		if (route_runtime.ready && reload_pending && route_generation_registry_retired(context->generations) == NULL
#ifdef LISTENER_READY_FLIP_TEST
			&& ready_flip_timer_ready
#endif
		) {
#ifdef LISTENER_EARLY_COLLECT_TEST
			if (listener_test_early_collect_observe(requests.resolver_ready, retired_before_collect) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
					"Cannot notify the early-collect test: %s",
					strerror(errno)
				);
				exitcode = EXITCODE_INTERNAL;
				break;
			}
#endif
			if (listener_notify_reloading() == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
					"Cannot create systemd reload timestamp: %s",
					strerror(errno)
				);
				exitcode = EXITCODE_INTERNAL;
				break;
			}
			if (!listener_events_hosts_watch_active(&events)) {
				listener_hosts_watch_retry(context, &events);
			}
			/* Arm monitoring before the manual hosts read so changes during that read remain observable. */
			int reload_result = listener_reload(context, listener, &events, &metrics_readiness_invalidated);
			/* Complete the reload handshake before acting on a fatal result; systemd observes the subsequent listener exit separately. */
			listener_notify_ready();
			hosts_reload_pending = false;
			reload_pending = false;
			if (reload_result == -1) {
				exitcode = EXITCODE_INTERNAL;
				break;
			}
			reload_processed = true;
			route_runtime.pressure_logged = false;
		}
		if (route_runtime.ready && !reload_pending && hosts_reload_pending && route_generation_registry_retired(context->generations) == NULL) {
			hosts_reload_pending = false;
			if (listener_hosts_reload(context) == -1) {
				exitcode = EXITCODE_INTERNAL;
				break;
			}
			reload_processed = true;
			route_runtime.pressure_logged = false;
		}
		bool route_activity = requests.accept_ready || requests.ready_count > 0 || requests.reload || requests.resolver_ready || requests.route_timer_ready || reload_processed;
		if (route_activity) {
			if (clock_gettime(CLOCK_MONOTONIC, &route_now) == -1 || listener_route_runtime_schedule(context, &route_runtime, &events, listener, &route_now) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
					"Proxy route prewarming failed: %s",
					strerror(errno)
				);
				exitcode = EXITCODE_INTERNAL;
				break;
			}
		}
		/* Consume socket data before timers from the same epoll batch, then reject only a still-current deadline. */
		for (int timeout_pass = 0; timeout_pass <= 1; timeout_pass++) {
			if (timeout_pass == 1 && clock_gettime(CLOCK_MONOTONIC, &route_now) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
					"Cannot sample the monotonic clock while processing connection deadlines: %s",
					strerror(errno)
				);
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
					progress = listener_connection_timeout(connection, requests.ready[ready_index].flags, requests.ready[ready_index].source_generation, &events, context, &route_now);
				} else if (connection->state == LISTENER_CONNECTION_INITIAL) {
					progress = kind == LISTENER_EVENT_CLIENT ? listener_connection_receive(connection, requests.ready[ready_index].flags, context) : LISTENER_CONNECTION_PENDING;
				} else if (connection->state == LISTENER_CONNECTION_ROUTE_WAITING) {
					progress = listener_connection_route_cancelled(connection, kind, requests.ready[ready_index].flags) ? LISTENER_CONNECTION_CLOSED : LISTENER_CONNECTION_PENDING;
				} else {
					progress = listener_short_event(connection, kind, requests.ready[ready_index].flags, requests.ready[ready_index].source_generation, &events, &route_now);
				}
				if (progress == LISTENER_CONNECTION_READY && connection->state == LISTENER_CONNECTION_INITIAL) {
					progress = listener_connection_route_start(connection, &events, &context->metrics, context->resolver, &route_now);
				}
				if (progress == LISTENER_CONNECTION_PENDING && listener_connection_route_cancelled(connection, kind, requests.ready[ready_index].flags)) {
					progress = LISTENER_CONNECTION_CLOSED;
				}
				if (progress == LISTENER_CONNECTION_READY) {
					progress = listener_connection_ready(connections, connection, listener, &events, listener_pid, context, &route_now);
				}
				if (progress == LISTENER_CONNECTION_FATAL) {
					LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
						"Connection state processing failed: %s",
						strerror(errno)
					);
					exitcode = EXITCODE_INTERNAL;
					goto cleanup;
				}
				listener_connection_finish(connection, progress, context->log_filename, context->config->log.level);
			}
#ifdef LISTENER_TIMER_REARM_TEST
			if (timeout_pass == 0 && listener_test_connection_timer_rearm(&requests) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
					"Cannot run the timer rearm regression hook: %s",
					strerror(errno)
				);
				exitcode = EXITCODE_INTERNAL;
				goto cleanup;
			}
#endif
		}
		size_t destroyed_count;
		if (!listener_connections_destroy_closed(&connections, &events, &context->metrics, context->resolver, &route_now, &destroyed_count)) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
				"Cannot release closed connection route interests: %s",
				strerror(errno)
			);
			exitcode = EXITCODE_INTERNAL;
			break;
		}
		if (destroyed_count > connection_count) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
				"Listener connection accounting failed."
			);
			exitcode = EXITCODE_INTERNAL;
			break;
		}
		connection_count -= destroyed_count;
		if (!listener_generation_collect(context, &route_now)) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
				"Cannot collect a retired proxy route generation after connection processing: %s",
				strerror(errno)
			);
			exitcode = EXITCODE_INTERNAL;
			break;
		}
		if (route_runtime.ready && (hosts_reload_pending || reload_pending) && route_generation_registry_retired(context->generations) == NULL) {
			if (clock_gettime(CLOCK_MONOTONIC, &route_now) == -1 || listener_route_timer_set(&events, &route_now) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
					"Cannot resume a deferred route-generation reload: %s",
					strerror(errno)
				);
				exitcode = EXITCODE_INTERNAL;
				break;
			}
#ifdef LISTENER_READY_FLIP_TEST
			if (listener_test_ready_flip_timer_arm() == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
					"Cannot notify the ready-flip late-wake test: %s",
					strerror(errno)
				);
				exitcode = EXITCODE_INTERNAL;
				break;
			}
#endif
		}
		listener_metrics_observations_drain(context, &route_now);
		if (!metrics_readiness_invalidated && (requests.metrics_timer_ready || requests.metrics_timer_failed)) {
			uint64_t expirations = 0;
			listener_metrics_timer_read_status metrics_status = listener_metrics_timer_read(context, &events, requests.metrics_timer_failed, &expirations);
			if (metrics_status == LISTENER_METRICS_TIMER_EXPIRED && listener_metrics_effectively_enabled(context->config)) {
				if (expirations > 1) {
					listener_metrics_missed_intervals_record(&context->metrics_runtime, expirations - 1U);
				}
				listener_metrics_snapshot_output(context, LISTENER_METRICS_OUTPUT_PERIODIC, context->log_filename, context->config->log.level, &route_now);
			}
		}
		if (!route_runtime.ready || !requests.accept_ready) {
			continue;
		}
		for (size_t accept_attempt = 0; accept_attempt < LISTENER_ACCEPT_BATCH; accept_attempt++) {
			struct sockaddr_storage client_address;
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
					listener_metrics_accept_fd_exhausted_record(&context->metrics);
					LISTENER_LOG(context, MKSYS_LEVEL_WARNING,
						"Cannot accept client connection: %s",
						strerror(errno)
					);
					listener_backoff();
					break;
				}
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
					"Cannot accept client connection: %s",
					strerror(errno)
				);
				exitcode = EXITCODE_INTERNAL;
				goto cleanup;
			}
			listener_metrics_accept_record(&context->metrics);
			net_addr peer_address;
			in_port_t peer_port;
			if (!net_addr_from_socket(&client_address, &peer_address, &peer_port)) {
				close(client_fd);
				continue;
			}
			net_addr_unmap(&peer_address);
			connection_proxy_origin origin = CONNECTION_PROXY_DIRECT;
			if (context->config->listen.allow_proxy) {
				if (config_peer_trusted(context->config, peer_address)) {
					origin = CONNECTION_PROXY_TRUSTED;
				} else if (context->config->listen.untrusted_policy == CONF_UNTRUSTED_REJECT) {
					listener_proxy_exception(context, &peer_address, peer_port, "untrusted_source", 0);
					close(client_fd);
					continue;
				} else {
					origin = context->config->listen.untrusted_policy == CONF_UNTRUSTED_IGNORE ? CONNECTION_PROXY_UNTRUSTED_IGNORE : CONNECTION_PROXY_UNTRUSTED_ACCEPT;
				}
			}
			if (connection_count >= connection_limit || context->workers.count >= connection_limit - connection_count) {
				listener_metrics_accept_capacity_rejected_record(&context->metrics);
				close(client_fd);
				continue;
			}
			route_generation *generation = route_generation_registry_active_retain(context->generations);
			if (generation == NULL) {
				close(client_fd);
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
					"Cannot retain the active route generation for a client connection."
				);
				exitcode = EXITCODE_INTERNAL;
				goto cleanup;
			}
			listener_connection *connection = listener_connection_create(client_fd, &peer_address, peer_port, &events, generation);
			if (connection == NULL) {
				int saved_errno = errno;
				listener_metrics_connection_track_failure_record(&context->metrics);
				LISTENER_LOG(context, MKSYS_LEVEL_WARNING,
					"Cannot track client connection: %s",
					strerror(saved_errno)
				);
				listener_backoff();
				break;
			}
			connection->proxy_origin = origin;
			connection->next = connections;
			connections = connection;
			connection_count++;
			listener_metrics_connection_add(&context->metrics);
		}
	}
cleanup: {
	struct timespec cleanup_now;
	const struct timespec *cleanup_now_ptr = clock_gettime(CLOCK_MONOTONIC, &cleanup_now) == 0 ? &cleanup_now : NULL;
	if (cleanup_now_ptr != NULL && context->resolver != NULL) {
		listener_metrics_observations_drain(context, cleanup_now_ptr);
	}
	while (connections != NULL) {
		listener_connection_destroy(&connections, connections, &events, &context->metrics, LISTENER_METRICS_OUTCOME_INTERNAL_ERROR, NULL, cleanup_now_ptr);
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
	log_stderr_prepare();
	LISTENER_LOG(&context, MKSYS_LEVEL_INFORMATION, "Starting mcrelay %s on PID %jd...", version_info_get(), (intmax_t)getpid());
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
		LISTENER_LOG(&context, MKSYS_LEVEL_CRITICAL, "Cannot prepare proxy routes: %s.", route_status == ROUTE_TABLE_BUILD_MEMORY ? "memory allocation failed" : "invalid internal route state");
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
