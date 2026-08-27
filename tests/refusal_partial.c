/*
 * refusal_partial.c: Deterministic worker-cap refusal send injection
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
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* section: global variables */
static bool refusal_send_eagain;
static int refusal_send_fd = -1;
static bool refusal_send_injected;

/* section: functions (exported) */
ssize_t __real_send(int socket_fd, const void *buffer, size_t size, int flags);

ssize_t __wrap_send(int socket_fd, const void *buffer, size_t size, int flags) {
	static const char notice[] = "[Proxy] Proxy is full, try again later.";
	const char *marker_filename = getenv("MCRELAY_TEST_REFUSAL_PARTIAL");
	if (marker_filename == NULL || refusal_send_injected) {
		return __real_send(socket_fd, buffer, size, flags);
	}
	if (refusal_send_eagain && socket_fd == refusal_send_fd) {
		int marker_fd = open(marker_filename, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
		if (marker_fd != -1) {
			close(marker_fd);
		}
		refusal_send_eagain = false;
		refusal_send_injected = true;
		errno = EAGAIN;
		return -1;
	}
	if (buffer == NULL || memmem(buffer, size, notice, sizeof(notice) - 1U) == NULL) {
		return __real_send(socket_fd, buffer, size, flags);
	}
	size_t partial_size = size < 8U ? size : 8U;
	ssize_t result = __real_send(socket_fd, buffer, partial_size, flags);
	if (result > 0 && (size_t)result < size) {
		refusal_send_eagain = true;
		refusal_send_fd = socket_fd;
	}
	return result;
}
