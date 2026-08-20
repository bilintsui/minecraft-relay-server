/*
 * network_connect.c: Tests for nonblocking outbound connections
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* section: headers (project) */
#include "network.h"

/* section: defines */
/* assertion */
#define CHECK(condition, message) \
	do { \
		if (!(condition)) { \
			fprintf(stderr, "%s (errno=%d)\n", message, errno); \
			goto cleanup; \
		} \
	} while (0)

/* section: global variables */
static bool connect_force_success;
int __real_connect(int socket_fd, const struct sockaddr *address, socklen_t address_size);

/* section: functions (local) */
static int connect_test_listener(in_port_t *port) {
	struct sockaddr_in address;
	socklen_t address_size = sizeof(address);
	int option = 1;
	int result;
	if (port == NULL) {
		errno = EINVAL;
		return -1;
	}
	result = socket(AF_INET, SOCK_STREAM, 0);
	if (result == -1) {
		return -1;
	}
	if (setsockopt(result, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) == -1) {
		close(result);
		return -1;
	}
	address = (struct sockaddr_in){
		.sin_family = AF_INET,
		.sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
		.sin_port = htons(0)
	};
	if (bind(result, (const struct sockaddr *)&address, sizeof(address)) == -1 || listen(result, 8) == -1
		|| getsockname(result, (struct sockaddr *)&address, &address_size) == -1) {
		close(result);
		return -1;
	}
	*port = ntohs(address.sin_port);
	return result;
}

static bool connect_test_poll(int socket_fd) {
	struct pollfd event = { .fd = socket_fd, .events = POLLOUT };
	int result;
	if (socket_fd < 0) {
		errno = EINVAL;
		return false;
	}
	result = poll(&event, 1, 1000);
	return result == 1 && (event.revents & (POLLOUT | POLLERR | POLLHUP)) != 0;
}

static bool connect_test_arguments(void) {
	bool test_result = false;
	int pipe_fds[2] = { -1, -1 };
	int socket_fd = 42;
	net_addr invalid = { .family = AF_UNSPEC };
	CHECK(net_connect_nonblocking(NULL, 1, &socket_fd) == NET_CONNECT_BAD_ARGUMENT && socket_fd == -1,
		"NULL address was accepted");
	socket_fd = 42;
	CHECK(net_connect_nonblocking(&invalid, 1, &socket_fd) == NET_CONNECT_BAD_ARGUMENT && socket_fd == -1,
		"invalid address family was accepted");
	socket_fd = 42;
	CHECK(net_connect_nonblocking(&invalid, 1, NULL) == NET_CONNECT_BAD_ARGUMENT,
		"NULL socket output was accepted");
	CHECK(net_connect_nonblocking_complete(-1) == NET_CONNECT_BAD_ARGUMENT,
		"negative completion socket was accepted");
	CHECK(pipe(pipe_fds) == 0, "could not create completion internal-error pipe");
	CHECK(net_connect_nonblocking_complete(pipe_fds[0]) == NET_CONNECT_INTERNAL,
		"non-socket completion descriptor was not rejected internally");
	close(pipe_fds[0]);
	close(pipe_fds[1]);
	pipe_fds[0] = -1;
	pipe_fds[1] = -1;
	socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	CHECK(socket_fd != -1, "could not create completion argument socket");
	CHECK(net_connect_nonblocking_complete(socket_fd) == NET_CONNECT_OK,
		"unconnected socket did not report a zero SO_ERROR");
	test_result = true;

cleanup:
	if (pipe_fds[0] >= 0) {
		close(pipe_fds[0]);
	}
	if (pipe_fds[1] >= 0) {
		close(pipe_fds[1]);
	}
	if (socket_fd >= 0) {
		close(socket_fd);
	}
	return test_result;
}

static bool connect_test_failure(void) {
	bool test_result = false;
	int socket_fd = -1;
	int listener_fd = -1;
	in_port_t port = 0;
	net_addr address = net_addr_parse("127.0.0.1");
	CHECK(address.family == AF_INET, "could not parse loopback address");
	listener_fd = connect_test_listener(&port);
	CHECK(listener_fd >= 0, "could not create refusal listener");
	close(listener_fd);
	listener_fd = -1;
	connect_force_success = false;
	net_connect_status status = net_connect_nonblocking(&address, port, &socket_fd);
	CHECK(status == NET_CONNECT_FAILURE || status == NET_CONNECT_PENDING, "refused connection had an unexpected status");
	if (status == NET_CONNECT_PENDING) {
		CHECK(connect_test_poll(socket_fd), "refused connection did not become ready");
		CHECK(net_connect_nonblocking_complete(socket_fd) == NET_CONNECT_FAILURE, "SO_ERROR did not report refusal");
		close(socket_fd);
		socket_fd = -1;
	}
	CHECK(socket_fd == -1, "immediate refusal left an open socket");
	test_result = true;

cleanup:
	if (listener_fd >= 0) {
		close(listener_fd);
	}
	if (socket_fd >= 0) {
		close(socket_fd);
	}
	return test_result;
}

static bool connect_test_immediate_success(void) {
	bool test_result = false;
	int listener_fd = -1;
	int socket_fd = -1;
	in_port_t port = 0;
	net_addr address = net_addr_parse("127.0.0.1");
	CHECK(address.family == AF_INET, "could not parse loopback address");
	listener_fd = connect_test_listener(&port);
	CHECK(listener_fd >= 0, "could not create immediate-connect listener");
	connect_force_success = true;
	CHECK(net_connect_nonblocking(&address, port, &socket_fd) == NET_CONNECT_OK,
		"immediate connect was not accepted");
	CHECK(socket_fd >= 0, "immediate connect did not return a socket");
	close(socket_fd);
	socket_fd = -1;
	test_result = true;

cleanup:
	connect_force_success = false;
	if (listener_fd >= 0) {
		close(listener_fd);
	}
	if (socket_fd >= 0) {
		close(socket_fd);
	}
	return test_result;
}

static bool connect_test_success(void) {
	bool test_result = false;
	int accepted_fd = -1;
	int listener_fd = -1;
	int socket_fd = -1;
	in_port_t port = 0;
	net_addr address = net_addr_parse("127.0.0.1");
	connect_force_success = false;
	CHECK(address.family == AF_INET, "could not parse loopback address");
	listener_fd = connect_test_listener(&port);
	CHECK(listener_fd >= 0, "could not create loopback listener");
	net_connect_status status = net_connect_nonblocking(&address, port, &socket_fd);
	CHECK(status == NET_CONNECT_OK || status == NET_CONNECT_PENDING, "loopback connection did not start");
	CHECK(socket_fd >= 0, "loopback connection did not return a socket");
	if (status == NET_CONNECT_PENDING) {
		CHECK(connect_test_poll(socket_fd), "loopback connection did not become ready");
	}
	CHECK(net_connect_nonblocking_complete(socket_fd) == NET_CONNECT_OK, "SO_ERROR did not report loopback success");
	accepted_fd = accept(listener_fd, NULL, NULL);
	CHECK(accepted_fd >= 0, "loopback listener did not accept the connection");
	CHECK((fcntl(socket_fd, F_GETFL) & O_NONBLOCK) != 0, "outbound socket was not nonblocking");
	CHECK((fcntl(socket_fd, F_GETFD) & FD_CLOEXEC) != 0, "outbound socket was not close-on-exec");
	test_result = true;

cleanup:
	if (accepted_fd >= 0) {
		close(accepted_fd);
	}
	if (listener_fd >= 0) {
		close(listener_fd);
	}
	if (socket_fd >= 0) {
		close(socket_fd);
	}
	return test_result;
}

/* section: functions (exported) */
int __wrap_connect(int socket_fd, const struct sockaddr *address, socklen_t address_size) {
	int result = __real_connect(socket_fd, address, address_size);
	if (connect_force_success) {
		if (result == 0 || errno == EINPROGRESS || errno == EALREADY || errno == EINTR) {
			return 0;
		}
	}
	return result;
}

/* section: functions (entry point) */
int main(void) {
	return connect_test_arguments() && connect_test_failure() && connect_test_immediate_success() && connect_test_success() ? EXIT_SUCCESS : EXIT_FAILURE;
}
