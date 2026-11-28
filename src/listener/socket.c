/*
 * listener/socket.c: Listening endpoints and socket replacement
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* section: headers (project) */
#include "../config.h"
#include "../network.h"
#include "events.h"

/* section: headers (self) */
#include "socket.h"

/* section: types */
typedef enum {
	LISTENER_SOCKET_OPEN_OK,
	LISTENER_SOCKET_OPEN_BIND_ERROR,
	LISTENER_SOCKET_OPEN_EVENTS_ERROR
} listener_socket_open_status;

/* section: functions (local) */
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

/* section: functions (exported) */
bool listener_endpoint_equal(const listener_endpoint *left, const listener_endpoint *right) {
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

listener_endpoint_status listener_endpoint_prepare(const conf *source, listener_endpoint *target) {
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

int listener_socket_bind(listener_socket *target) {
	target->fd = net_socket(NETSOCK_BIND, target->endpoint.address.family, &(target->endpoint.address.addr), target->endpoint.port, true);
	return target->fd;
}

void listener_socket_close(listener_socket *target) {
	if (target->fd != -1) {
		close(target->fd);
		target->fd = -1;
	}
}

listener_socket_replace_status listener_socket_replace(listener_socket *target, const listener_endpoint *endpoint, const listener_events *events) {
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
