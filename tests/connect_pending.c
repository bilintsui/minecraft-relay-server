/*
 * connect_pending.c: Deterministic pending-connect injection for listener integration tests
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/* section: headers (library) */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* section: global variables */
static int connect_pending_peer = -1;

/* section: functions (exported) */
int __real_connect(int socket_fd, const struct sockaddr *address, socklen_t address_size);

int __wrap_connect(int socket_fd, const struct sockaddr *address, socklen_t address_size) {
	if (getenv("MCRELAY_TEST_CONNECT_PENDING") == NULL || address == NULL || (address->sa_family != AF_INET && address->sa_family != AF_INET6)) {
		return __real_connect(socket_fd, address, address_size);
	}
	int sockets[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sockets) == -1) {
		return -1;
	}
	uint8_t buffer[4096] = { 0 };
	ssize_t send_size;
	do {
		send_size = send(sockets[0], buffer, sizeof(buffer), MSG_NOSIGNAL);
	} while (send_size > 0 || (send_size == -1 && errno == EINTR));
	if (send_size != -1) {
		close(sockets[0]);
		close(sockets[1]);
		errno = EIO;
		return -1;
	}
	if (errno != EAGAIN && errno != EWOULDBLOCK) {
		int saved_errno = errno;
		close(sockets[0]);
		close(sockets[1]);
		errno = saved_errno;
		return -1;
	}
	if (dup3(sockets[0], socket_fd, O_CLOEXEC) == -1) {
		int saved_errno = errno;
		close(sockets[0]);
		close(sockets[1]);
		errno = saved_errno;
		return -1;
	}
	close(sockets[0]);
	if (connect_pending_peer != -1) {
		close(connect_pending_peer);
	}
	connect_pending_peer = sockets[1];
	errno = EINPROGRESS;
	return -1;
}
