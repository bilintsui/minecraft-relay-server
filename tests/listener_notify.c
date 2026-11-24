/*
 * listener_notify.c: Startup notification wait support for listener tests
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>

/* section: headers (self) */
#include "listener_notify.h"

/* section: functions (local) */
static int64_t listener_test_notify_milliseconds(void) {
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
		return -1;
	}
	return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

/* section: functions (exported) */
ssize_t listener_test_notify_wait(int socket_fd, pid_t *child, char *message, size_t capacity, int timeout_ms, int *child_status) {
	if (socket_fd < 0 || child == NULL || *child <= 0 || message == NULL || capacity < 2 || capacity > INT_MAX || timeout_ms <= 0 || child_status == NULL) {
		errno = EINVAL;
		return -1;
	}
	message[0] = '\0';
	*child_status = 0;
	int64_t started = listener_test_notify_milliseconds();
	if (started < 0) {
		return -1;
	}
	for (;;) {
		pid_t waited = waitpid(*child, child_status, WNOHANG);
		if (waited == *child) {
			*child = -1;
			errno = ECHILD;
			return -1;
		}
		if (waited == -1 && errno != EINTR) {
			return -1;
		}
		int64_t now = listener_test_notify_milliseconds();
		if (now < 0) {
			return -1;
		}
		int64_t remaining = timeout_ms - (now - started);
		if (remaining <= 0) {
			errno = ETIMEDOUT;
			return -1;
		}
		struct pollfd event = { .fd = socket_fd, .events = POLLIN };
		int ready = poll(&event, 1, remaining < 100 ? (int)remaining : 100);
		if (ready == -1 && errno != EINTR) {
			return -1;
		}
		if (ready <= 0) {
			continue;
		}
		if (!(event.revents & POLLIN)) {
			errno = EIO;
			return -1;
		}
		ssize_t size = recv(socket_fd, message, capacity - 1, MSG_DONTWAIT | MSG_TRUNC);
		if (size == -1 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
			continue;
		}
		if (size <= 0 || (size_t)size >= capacity) {
			errno = size < 0 ? errno : size == 0 ? EPROTO : EMSGSIZE;
			return -1;
		}
		message[size] = '\0';
		return size;
	}
}
