/*
 * network.c: Functions for fundamental communications
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* section: headers (self) */
#include "network.h"

/* section: types */
typedef enum {
	NET_RELAY_POLL_IN,
	NET_RELAY_POLL_OUT,
	NET_RELAY_POLL_COUNT
} net_relay_poll_index;
typedef struct {
	size_t offset;
	size_t length;
	bool peer_eof;
	bool shutdown_sent;
	uint8_t data[NET_RELAY_BUFFER_BYTES];
} net_relay_queue;

/* section: functions (local) */
static bool net_relay_finished(const net_relay_queue *queue_c2o, const net_relay_queue *queue_o2c) {
	return queue_c2o->peer_eof && queue_o2c->peer_eof && queue_c2o->offset == queue_c2o->length && queue_o2c->offset == queue_o2c->length
		&& queue_c2o->shutdown_sent && queue_o2c->shutdown_sent;
}

static int net_relay_idle_remaining_ms(const struct timespec *last_activity, const struct timespec *now) {
	int64_t elapsed_seconds;
	int64_t elapsed_nanoseconds;
	int64_t remaining_seconds;
	int64_t remaining_nanoseconds = 0;
	if (now->tv_nsec < last_activity->tv_nsec) {
		elapsed_seconds = (int64_t)now->tv_sec - (int64_t)last_activity->tv_sec - 1;
		elapsed_nanoseconds = (int64_t)now->tv_nsec + INT64_C(1000000000) - (int64_t)last_activity->tv_nsec;
	} else {
		elapsed_seconds = (int64_t)now->tv_sec - (int64_t)last_activity->tv_sec;
		elapsed_nanoseconds = (int64_t)now->tv_nsec - (int64_t)last_activity->tv_nsec;
	}
	if (elapsed_seconds < 0) {
		return 0;
	}
	if (elapsed_seconds > (int64_t)NET_RELAY_IDLE_TIMEOUT_SEC
		|| (elapsed_seconds == (int64_t)NET_RELAY_IDLE_TIMEOUT_SEC && elapsed_nanoseconds > 0)) {
		return 0;
	}
	remaining_seconds = (int64_t)NET_RELAY_IDLE_TIMEOUT_SEC - elapsed_seconds;
	if (elapsed_nanoseconds > 0) {
		remaining_seconds--;
		remaining_nanoseconds = INT64_C(1000000000) - elapsed_nanoseconds;
	}
	if (remaining_seconds > INT_MAX / 1000) {
		return INT_MAX;
	}
	int64_t remaining_milliseconds = remaining_seconds * INT64_C(1000) + (remaining_nanoseconds + INT64_C(999999)) / INT64_C(1000000);
	return remaining_milliseconds > INT_MAX ? INT_MAX : (int)remaining_milliseconds;
}

static bool net_relay_mark_activity(struct timespec *last_activity) {
	return clock_gettime(CLOCK_MONOTONIC, last_activity) == 0;
}

static void net_relay_queue_compact(net_relay_queue *queue) {
	if (queue->offset == 0) {
		return;
	}
	if (queue->offset == queue->length) {
		queue->offset = 0;
		queue->length = 0;
		return;
	}
	memmove(queue->data, queue->data + queue->offset, queue->length - queue->offset);
	queue->length -= queue->offset;
	queue->offset = 0;
}

static bool net_relay_queue_drain(net_relay_queue *queue, int socket_fd, struct timespec *last_activity) {
	while (queue->offset < queue->length) {
		ssize_t sent = send(socket_fd, queue->data + queue->offset, queue->length - queue->offset, MSG_NOSIGNAL);
		if (sent > 0) {
			queue->offset += (size_t)sent;
			if (!net_relay_mark_activity(last_activity)) {
				return false;
			}
			continue;
		}
		if ((sent < 0) && (errno == EINTR)) {
			continue;
		}
		if ((sent < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK))) {
			break;
		}
		return false;
	}
	net_relay_queue_compact(queue);
	return true;
}

static bool net_relay_queue_fill(net_relay_queue *queue, int socket_fd, struct timespec *last_activity) {
	net_relay_queue_compact(queue);
	while ((!queue->peer_eof) && (queue->length < NET_RELAY_BUFFER_BYTES)) {
		ssize_t received = recv(socket_fd, queue->data + queue->length, NET_RELAY_BUFFER_BYTES - queue->length, 0);
		if (received > 0) {
			queue->length += (size_t)received;
			if (!net_relay_mark_activity(last_activity)) {
				return false;
			}
			continue;
		}
		if (received == 0) {
			queue->peer_eof = true;
			break;
		}
		if ((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK)) {
			break;
		}
		return false;
	}
	return true;
}

static bool net_relay_shutdown_propagate(net_relay_queue *queue, int socket_fd) {
	if ((!queue->peer_eof) || (queue->offset < queue->length) || queue->shutdown_sent) {
		return true;
	}
	if (shutdown(socket_fd, SHUT_WR) == -1) {
		if ((errno == ECONNRESET) || (errno == ENOTCONN) || (errno == EPIPE)) {
			queue->shutdown_sent = true;
			return true;
		}
		return false;
	}
	queue->shutdown_sent = true;
	return true;
}

/* section: functions (exported) */
net_addr net_addr_parse(const char *address) {
	net_addr result;
	memset(&result, 0, sizeof(result));
	if (address != NULL && inet_pton(AF_INET, address, &result.addr.v4) == 1) {
		result.family = AF_INET;
		return result;
	}
	memset(&result.addr, 0, sizeof(result.addr));
	if (address != NULL && inet_pton(AF_INET6, address, result.addr.v6) == 1) {
		result.family = AF_INET6;
		return result;
	}
	result.err = NET_EARGADDR;
	return result;
}

net_connect_status net_connect_nonblocking(const net_addr *address, in_port_t port, int *socket_fd) {
	struct sockaddr_in address_v4;
	struct sockaddr_in6 address_v6;
	socklen_t address_size;
	const struct sockaddr *socket_address;
	int connect_error, result;
	if (socket_fd == NULL || address == NULL || address->err != NET_OK || ((address->family != AF_INET) && (address->family != AF_INET6))) {
		if (socket_fd != NULL) {
			*socket_fd = -1;
		}
		errno = NET_EARGADDR;
		return NET_CONNECT_BAD_ARGUMENT;
	}
	*socket_fd = -1;
	if (address->family == AF_INET) {
		memset(&address_v4, 0, sizeof(address_v4));
		address_v4.sin_family = AF_INET;
		address_v4.sin_port = htons(port);
		memcpy(&address_v4.sin_addr, &address->addr.v4, sizeof(address_v4.sin_addr));
		address_size = sizeof(address_v4);
		socket_address = (const struct sockaddr *)&address_v4;
	} else {
		memset(&address_v6, 0, sizeof(address_v6));
		address_v6.sin6_family = AF_INET6;
		address_v6.sin6_port = htons(port);
		memcpy(&address_v6.sin6_addr, &address->addr.v6, sizeof(address_v6.sin6_addr));
		address_size = sizeof(address_v6);
		socket_address = (const struct sockaddr *)&address_v6;
	}
	result = socket(address->family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (result == -1) {
		return NET_CONNECT_INTERNAL;
	}
	if (connect(result, socket_address, address_size) == 0) {
		*socket_fd = result;
		return NET_CONNECT_OK;
	}
	if ((errno == EINPROGRESS) || (errno == EALREADY) || (errno == EINTR)) {
		*socket_fd = result;
		return NET_CONNECT_PENDING;
	}
	connect_error = errno;
	close(result);
	errno = connect_error;
	return NET_CONNECT_FAILURE;
}

net_connect_status net_connect_nonblocking_complete(int socket_fd) {
	int socket_error;
	socklen_t socket_error_size = sizeof(socket_error);
	if (socket_fd < 0) {
		errno = NET_EARGADDR;
		return NET_CONNECT_BAD_ARGUMENT;
	}
	if (getsockopt(socket_fd, SOL_SOCKET, SO_ERROR, &socket_error, &socket_error_size) == -1) {
		return NET_CONNECT_INTERNAL;
	}
	if (socket_error != 0) {
		errno = socket_error;
		return NET_CONNECT_FAILURE;
	}
	return NET_CONNECT_OK;
}

net_addrp net_ntop(sa_family_t family, const void *src, bool v6addition) {
	net_addrp pre_result;
	memset(&pre_result, 0, sizeof(pre_result));
	if (((family != AF_INET) && (family != AF_INET6)) || (src == NULL) || (inet_ntop(family, src, (char *)&pre_result, sizeof(pre_result)) == NULL)) {
		return pre_result;
	}
	if ((v6addition) && (family == AF_INET6)) {
		net_addrp result;
		memset(&result, 0, sizeof(result));
		snprintf((char *)&result, sizeof(result), "[%s]", (char *)&pre_result);
		return result;
	}
	return pre_result;
}

/*
 * net_relay - bidirectional relay between two nonblocking sockets.
 * Each direction has a bounded queue.  pending_out is copied into the
 * client-to-upstream queue before any client bytes are read.
 */
net_relay_status net_relay(int socket_in, int socket_out, const void *pending_out, size_t pending_size) {
	net_relay_queue queue_c2o = { 0 };
	net_relay_queue queue_o2c = { 0 };
	struct pollfd events[NET_RELAY_POLL_COUNT];
	struct timespec last_activity;
	net_relay_status result = NET_RELAY_ERROR;
	int cleanup_errno;
	if ((socket_in < 0) || (socket_out < 0) || (socket_in == socket_out) || ((pending_out == NULL) && (pending_size > 0))
		|| (pending_size > NET_RELAY_BUFFER_BYTES)) {
		errno = EINVAL;
		goto cleanup;
	}
	if (clock_gettime(CLOCK_MONOTONIC, &last_activity) == -1) {
		goto cleanup;
	}
	int flags_in = fcntl(socket_in, F_GETFL);
	int flags_out = fcntl(socket_out, F_GETFL);
	if ((flags_in == -1) || (flags_out == -1) || (fcntl(socket_in, F_SETFL, flags_in | O_NONBLOCK) == -1)
		|| (fcntl(socket_out, F_SETFL, flags_out | O_NONBLOCK) == -1)) {
		goto cleanup;
	}
	if (pending_size > 0) {
		memcpy(queue_c2o.data, pending_out, pending_size);
		queue_c2o.length = pending_size;
	}
	while (true) {
		bool want_read_in = (!queue_c2o.peer_eof) && (queue_c2o.length - queue_c2o.offset < NET_RELAY_BUFFER_BYTES);
		bool want_read_out = (!queue_o2c.peer_eof) && (queue_o2c.length - queue_o2c.offset < NET_RELAY_BUFFER_BYTES);
		bool want_write_in = (!queue_o2c.shutdown_sent) && (queue_o2c.offset < queue_o2c.length);
		bool want_write_out = (!queue_c2o.shutdown_sent) && (queue_c2o.offset < queue_c2o.length);
		if (net_relay_finished(&queue_c2o, &queue_o2c)) {
			result = NET_RELAY_CLOSED;
			break;
		}
		events[NET_RELAY_POLL_IN] = (struct pollfd){
			.fd = want_read_in || want_write_in ? socket_in : -1,
			.events = (short)((want_read_in ? POLLIN | POLLRDHUP : 0) | (want_write_in ? POLLOUT : 0))
		};
		events[NET_RELAY_POLL_OUT] = (struct pollfd){
			.fd = want_read_out || want_write_out ? socket_out : -1,
			.events = (short)((want_read_out ? POLLIN | POLLRDHUP : 0) | (want_write_out ? POLLOUT : 0))
		};
		struct timespec now;
		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
			goto cleanup;
		}
		int wait_ms = net_relay_idle_remaining_ms(&last_activity, &now);
		if (wait_ms == 0) {
			result = NET_RELAY_IDLE;
			break;
		}
		int nfds = poll(events, NET_RELAY_POLL_COUNT, wait_ms);
		if (nfds == 0) {
			result = NET_RELAY_IDLE;
			break;
		}
		if (nfds == -1) {
			if (errno == EINTR) {
				continue;
			}
			goto cleanup;
		}
		for (int event_index = 0; event_index < NET_RELAY_POLL_COUNT; event_index++) {
			if (events[event_index].revents & POLLNVAL) {
				errno = EIO;
				goto cleanup;
			}
		}
		for (int event_index = NET_RELAY_POLL_IN; event_index < NET_RELAY_POLL_COUNT; event_index++) {
			int socket_fd = event_index == NET_RELAY_POLL_IN ? socket_in : socket_out;
			net_relay_queue *read_queue = event_index == NET_RELAY_POLL_IN ? &queue_c2o : &queue_o2c;
			net_relay_queue *write_queue = event_index == NET_RELAY_POLL_IN ? &queue_o2c : &queue_c2o;
			size_t queued_before = read_queue->length - read_queue->offset;
			if ((queued_before < NET_RELAY_BUFFER_BYTES) && (events[event_index].revents & (POLLIN | POLLRDHUP | POLLHUP | POLLERR))
				&& (!net_relay_queue_fill(read_queue, socket_fd, &last_activity))) {
				goto cleanup;
			}
			if ((write_queue->offset < write_queue->length) && (events[event_index].revents & (POLLOUT | POLLHUP | POLLERR))
				&& (!net_relay_queue_drain(write_queue, socket_fd, &last_activity))) {
				goto cleanup;
			}
			if ((events[event_index].revents & (POLLHUP | POLLERR)) && (!read_queue->peer_eof)
				&& (queued_before == read_queue->length - read_queue->offset) && (queued_before < NET_RELAY_BUFFER_BYTES)) {
				errno = EIO;
				goto cleanup;
			}
			if ((events[event_index].revents & (POLLHUP | POLLERR)) && (write_queue->offset < write_queue->length)) {
				errno = EPIPE;
				goto cleanup;
			}
		}
		if ((!net_relay_shutdown_propagate(&queue_c2o, socket_out)) || (!net_relay_shutdown_propagate(&queue_o2c, socket_in))) {
			goto cleanup;
		}
	}
cleanup:
	cleanup_errno = errno;
	if (socket_in >= 0) {
		close(socket_in);
	}
	if ((socket_out >= 0) && (socket_out != socket_in)) {
		close(socket_out);
	}
	if (result == NET_RELAY_ERROR) {
		errno = cleanup_errno;
	}
	return result;
}

int net_socket(net_socket_action action, sa_family_t family, const void *address, in_port_t port, bool reuseaddr) {
	if ((action != NETSOCK_BIND) && (action != NETSOCK_CONN)) {
		errno = NET_EARGACTION;
		return -1;
	}
	if ((family != AF_INET) && (family != AF_INET6)) {
		errno = NET_EARGFAMILY;
		return -1;
	}
	if (address == NULL) {
		errno = NET_EARGADDR;
		return -1;
	}
	void *serv_addr = NULL;
	socklen_t stru_size = 0;
	if (family == AF_INET) {
		stru_size = sizeof(struct sockaddr_in);
		serv_addr = malloc(stru_size);
		if (serv_addr == NULL) {
			errno = NET_EMALLOC;
			return -1;
		}
		memset(serv_addr, 0, stru_size);
		struct sockaddr_in *addr = serv_addr;
		addr->sin_family = AF_INET;
		addr->sin_port = htons(port);
		memcpy(&(addr->sin_addr.s_addr), address, sizeof(uint32_t));
	} else if (family == AF_INET6) {
		stru_size = sizeof(struct sockaddr_in6);
		serv_addr = malloc(stru_size);
		if (serv_addr == NULL) {
			errno = NET_EMALLOC;
			return -1;
		}
		memset(serv_addr, 0, stru_size);
		struct sockaddr_in6 *addr = serv_addr;
		addr->sin6_family = AF_INET6;
		addr->sin6_port = htons(port);
		memcpy(&(addr->sin6_addr), address, sizeof(uint8_t) * 16);
	}
	int result = socket(family, SOCK_STREAM, 0);
	if (result == -1) {
		free(serv_addr);
		errno = NET_ESOCKET;
		return -1;
	}
	if (reuseaddr) {
		int socket_opt = 1;
		if (setsockopt(result, SOL_SOCKET, SO_REUSEADDR, &socket_opt, sizeof(socket_opt)) == -1) {
			free(serv_addr);
			close(result);
			errno = NET_EREUSEADDR;
			return -1;
		}
	}
	if (action == NETSOCK_BIND) {
		if (bind(result, serv_addr, stru_size) == -1) {
			free(serv_addr);
			close(result);
			errno = NET_EBIND;
			return -1;
		} else {
			/* Linux caps INT_MAX to the current net.core.somaxconn value. */
			if (listen(result, INT_MAX) == -1) {
				free(serv_addr);
				close(result);
				errno = NET_ELISTEN;
				return -1;
			}
		}
	} else if (action == NETSOCK_CONN) {
		if (connect(result, serv_addr, stru_size) == -1) {
			free(serv_addr);
			close(result);
			errno = NET_ECONNECT;
			return -1;
		}
	}
	free(serv_addr);
	return result;
}
