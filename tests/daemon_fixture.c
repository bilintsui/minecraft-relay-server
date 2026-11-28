/*
 * daemon_fixture.c: Process and loopback socket support for daemon integration tests
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* section: headers (self) */
#include "daemon_fixture.h"

/* section: functions (local) */
static int loopback_bind(int fd, in_port_t *port) {
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK)
	};
	socklen_t length = sizeof(address);
	if (bind(fd, (struct sockaddr *)&address, sizeof(address)) == -1 || getsockname(fd, (struct sockaddr *)&address, &length) == -1) {
		return -1;
	}
	*port = ntohs(address.sin_port);
	return 0;
}

static int socket_close_error(int fd) {
	int saved_errno = errno;
	close(fd);
	errno = saved_errno;
	return -1;
}

/* section: functions (exported) */
pid_t test_child_start(const char *binary, const char *config_filename, const char *notify_socket) {
	pid_t child = fork();
	if (child != 0) {
		return child;
	}
	int devnull_fd = open("/dev/null", O_WRONLY);
	if (devnull_fd == -1 || dup2(devnull_fd, STDOUT_FILENO) == -1 || dup2(devnull_fd, STDERR_FILENO) == -1 || setenv("NOTIFY_SOCKET", notify_socket, 1) == -1) {
		_exit(EXIT_FAILURE);
	}
	if (devnull_fd > STDERR_FILENO) {
		close(devnull_fd);
	}
	execl(binary, binary, "run", "-c", config_filename, (char *)NULL);
	_exit(EXIT_FAILURE);
}

int test_child_wait(pid_t child, int timeout_ms) {
	const struct timespec interval = {
		.tv_nsec = 10000000
	};
	for (int elapsed_ms = 0; elapsed_ms < timeout_ms; elapsed_ms += 10) {
		int status;
		pid_t wait_result = waitpid(child, &status, WNOHANG);
		if (wait_result == child) {
			return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
		}
		if (wait_result == -1) {
			return -1;
		}
		nanosleep(&interval, NULL);
	}
	errno = ETIMEDOUT;
	return -1;
}

int test_client_connect(in_port_t port) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1) {
		return -1;
	}
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = htons(port)
	};
	if (connect(fd, (struct sockaddr *)&address, sizeof(address)) == -1) {
		return socket_close_error(fd);
	}
	return fd;
}

ssize_t test_notify_receive(int socket_fd, char *message, size_t message_size, int timeout_ms) {
	struct pollfd poll_fd = {
		.fd = socket_fd,
		.events = POLLIN
	};
	int poll_result;
	do {
		poll_result = poll(&poll_fd, 1, timeout_ms);
	} while (poll_result == -1 && errno == EINTR);
	if (poll_result <= 0) {
		return poll_result;
	}
	if (!(poll_fd.revents & POLLIN)) {
		errno = EIO;
		return -1;
	}
	ssize_t message_length = recv(socket_fd, message, message_size - 1, 0);
	if (message_length >= 0) {
		message[message_length] = '\0';
	}
	return message_length;
}

int test_port_find(in_port_t *result) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1) {
		return -1;
	}
	if (loopback_bind(fd, result) == -1) {
		return socket_close_error(fd);
	}
	return close(fd);
}

int test_server_open(in_port_t *port) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1) {
		return -1;
	}
	int reuse_address = 1;
	in_port_t bound_port;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse_address, sizeof(reuse_address)) == -1 || loopback_bind(fd, &bound_port) == -1 || listen(fd, 1) == -1) {
		return socket_close_error(fd);
	}
	*port = bound_port;
	return fd;
}

int test_socket_send_all(int socket_fd, const void *data, size_t size) {
	const uint8_t *bytes = data;
	size_t sent = 0;
	while (sent < size) {
		ssize_t send_result = send(socket_fd, bytes + sent, size - sent, MSG_NOSIGNAL);
		if (send_result == -1 && errno == EINTR) {
			continue;
		}
		if (send_result <= 0) {
			return -1;
		}
		sent += (size_t)send_result;
	}
	return 0;
}
