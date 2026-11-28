/*
 * listener/connection.c: Listener-owned connection lifecycle and deadlines
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

/* section: headers (project) */
#include "../config.h"
#include "../connection/setup.h"
#include "../connection/setup_short.h"
#include "../log.h"
#include "../network.h"
#include "../protocol/handshake.h"
#include "../resolver/supervisor.h"
#include "../route/generation.h"
#include "../route/waiter.h"
#include "../timeutil.h"
#include "events.h"
#include "metrics.h"

/* section: headers (self) */
#include "connection.h"

/* section: defines */
/* connection capacity */
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

/* connection deadlines */
#ifndef LISTENER_INITIAL_TIMEOUT_SEC
#define LISTENER_INITIAL_TIMEOUT_SEC	10
#endif
#ifndef LISTENER_LEGACY_PING_GRACE_MS
#define LISTENER_LEGACY_PING_GRACE_MS	100
#endif
#ifndef LISTENER_SHORT_LIFETIME_TIMEOUT_SEC
#define LISTENER_SHORT_LIFETIME_TIMEOUT_SEC	30
#endif

/* section: functions (local) */
static net_addrbundle listener_client_address_format(const net_addr *address, in_port_t port) {
	return (net_addrbundle){
		.family = address->family,
		.address = net_ntop(address->family, &address->addr, true),
		.address_clean = net_ntop(address->family, &address->addr, false),
		.port = port
	};
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

static connection_proxy_provenance listener_connection_provenance(const listener_connection *connection) {
	connection_proxy_provenance result = { .origin = connection->prefix_checked ? connection->proxy_origin : CONNECTION_PROXY_DIRECT };
	if (result.origin != CONNECTION_PROXY_DIRECT) {
		result.peer = net_ntop(connection->peer_address.family, &connection->peer_address.addr, true);
		result.peer_port = connection->peer_port;
	}
	return result;
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

/* section: functions (exported) */
net_addrbundle listener_connection_client(const listener_connection *connection) {
	if (connection->prefix_checked && connection->inbound_proxy.family != AF_UNSPEC) {
		return listener_client_address_format(&connection->inbound_proxy.srcaddr, connection->inbound_proxy.srcport);
	}
	return listener_client_address_format(&connection->peer_address, connection->peer_port);
}

listener_connection *listener_connection_create(int client_fd, const net_addr *peer_address, in_port_t peer_port, const listener_events *events, route_generation *generation) {
	listener_connection *connection = calloc(1, sizeof(*connection));
	if (connection == NULL) {
		close(client_fd);
		route_generation_release(generation);
		return NULL;
	}
	connection->peer_address = *peer_address;
	connection->peer_port = peer_port;
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

bool listener_connection_destroy(listener_connection **connections, listener_connection *target, const listener_events *events, listener_metrics_state *metrics,
	listener_metrics_outcome unsettled_outcome, resolver_supervisor *supervisor, const struct timespec *now) {
	listener_connection **current = connections;
	while (*current != NULL && *current != target) {
		current = &(*current)->next;
	}
	if (*current == NULL) {
		return true;
	}
	*current = target->next;
	if (target->route_metrics.pending) {
		(void)listener_metrics_route_resolution_record(metrics, &target->route_metrics, LISTENER_METRICS_RESOLUTION_WAITED);
	}
	(void)listener_metrics_route_settle(metrics, &target->route_metrics, unsettled_outcome, LISTENER_METRICS_SELECTED_FAMILY_NONE, now);
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
		if (!result) {
			(void)listener_metrics_route_release_failure_record(metrics, &target->route_metrics);
		}
	}
	int saved_errno = errno;
	route_generation_release(target->generation);
	listener_metrics_connection_remove(metrics);
	free(target);
	errno = saved_errno;
	return result;
}

void listener_connection_finish(listener_connection *connection, listener_connection_progress progress, const char *log_filename, uint8_t log_level) {
	if (progress != LISTENER_CONNECTION_ABORT && progress != LISTENER_CONNECTION_CLOSED) {
		return;
	}
	if (progress == LISTENER_CONNECTION_ABORT) {
		connection_proxy_provenance proxy = listener_connection_provenance(connection);
		net_addrbundle client = listener_connection_client(connection);
		const char *details = connection->state == LISTENER_CONNECTION_INITIAL ? "status: abort_init" : "status: abort_short";
		connection_setup_log_record(log_filename, log_level, MKSYS_LEVEL_WARNING, &proxy, &client, details);
	}
	connection->closing = true;
}

int listener_connection_interests_update(listener_connection *connection, const listener_events *events) {
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

size_t listener_connection_limit(void) {
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

bool listener_connection_route_release(listener_connection *connection, listener_metrics_state *metrics, resolver_supervisor *supervisor, const struct timespec *now) {
	if (connection == NULL || connection->generation == NULL) {
		return false;
	}
	route_waiter_destroy_status destroy_status = route_waiter_destroy(connection->waiter, supervisor, now);
	bool result = destroy_status == ROUTE_WAITER_DESTROY_OK;
	if (!result) {
		(void)listener_metrics_route_release_failure_record(metrics, &connection->route_metrics);
		errno = destroy_status == ROUTE_WAITER_DESTROY_IO ? EIO : destroy_status == ROUTE_WAITER_DESTROY_TIME ? EOVERFLOW : EINVAL;
	}
	int saved_errno = errno;
	connection->waiter = NULL;
	route_generation_release(connection->generation);
	connection->generation = NULL;
	errno = saved_errno;
	return result;
}

bool listener_connection_snapshot_prepare(const listener_connection *connection, const char *working_directory, connection_setup_snapshot *result) {
	if (connection == NULL || connection->generation == NULL || working_directory == NULL || result == NULL) {
		return false;
	}
	const conf *config = route_generation_config(connection->generation);
	const char *icon_b64 = config == NULL || config->icon_b64 == NULL ? FAVICON_BASE64 : config->icon_b64;
	size_t icon_size = strlen(icon_b64);
	if (config == NULL || config->log.filename == NULL || icon_size > CONF_ICON_B64MAX) {
		return false;
	}
	memset(result, 0, sizeof(*result));
	memcpy(result->icon_b64, icon_b64, icon_size + 1U);
	int log_filename_size = config->log.filename[0] == '/'
		? snprintf(result->log_filename, sizeof(result->log_filename), "%s", config->log.filename)
		: snprintf(result->log_filename, sizeof(result->log_filename), "%s/%s", working_directory, config->log.filename);
	if (log_filename_size < 0 || (size_t)log_filename_size >= sizeof(result->log_filename)) {
		return false;
	}
	result->log_level = config->log.level;
	result->proxy = listener_connection_provenance(connection);
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

int listener_connection_timer_arm(listener_connection *connection, listener_connection_timer timer) {
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

int listener_connection_timer_arm_short(listener_connection *connection, listener_connection_timer timer, const struct timespec *now, uint64_t seconds) {
	struct timespec expiration;
	return timeutil_add_seconds(now, seconds, &expiration) ? listener_connection_timer_set(connection, timer, &expiration) : -1;
}

int listener_connection_timer_set(listener_connection *connection, listener_connection_timer timer, const struct timespec *expiration) {
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
	connection->timer_source.generation = connection->timer_source.generation == UINT64_MAX ? 1 : connection->timer_source.generation + 1U;
	return 0;
}

void listener_connections_close_except(listener_connection *connections, const listener_connection *except) {
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

bool listener_connections_destroy_closed(listener_connection **connections, const listener_events *events, listener_metrics_state *metrics,
	resolver_supervisor *supervisor, const struct timespec *now, size_t *destroyed_count) {
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
			bool destroyed = listener_connection_destroy(connections, connection, events, metrics, LISTENER_METRICS_OUTCOME_ABANDONED, supervisor, now);
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
