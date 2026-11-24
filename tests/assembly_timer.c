/*
 * assembly_timer.c: Linker wrappers used only by listener_assembly_daemon
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

/* section: headers (self) */
#include "assembly_timer.h"

/* section: global variables */
static struct timespec assembly_clock;
static bool assembly_clock_valid;
static bool assembly_expired;
static assembly_timer_fault assembly_fault;
static bool assembly_fault_loaded;
static int assembly_identity_fd = -1;
static uint64_t assembly_input_bytes;
static bool assembly_io_delayed;
static int assembly_socket_fd = -1;
static int assembly_timer_clock_id;
static int assembly_timer_fd = -1;

/* section: functions (local) */
static int assembly_timer_channel(void) {
	int saved_errno = errno;
	const char *text = getenv(ASSEMBLY_TIMER_CHANNEL_ENV);
	char *end;
	errno = 0;
	long fd = text == NULL ? -1 : strtol(text, &end, 10);
	if (text == NULL || errno != 0 || *text == '\0' || *end != '\0' || fd < 3 || fd > INT_MAX) {
		_exit(ASSEMBLY_TIMER_CHANNEL_FAILURE);
	}
	errno = saved_errno;
	return (int)fd;
}

static void assembly_timer_event_send(assembly_timer_event_kind kind, int fd, int flags, int result, int error, const struct itimerspec *setting, uint64_t expirations) {
	int saved_errno = errno;
	assembly_timer_event event;
	memset(&event, 0, sizeof(event));
	event.magic = ASSEMBLY_TIMER_MAGIC;
	event.kind = kind;
	event.pid = getpid();
	event.fd = fd;
	event.socket_fd = assembly_identity_fd;
	event.flags = flags;
	event.result = result;
	event.error = error;
	event.clock_id = assembly_timer_clock_id;
	event.initial_clock_valid = assembly_clock_valid;
	event.input_bytes = assembly_input_bytes;
	event.expirations = expirations;
	event.initial_clock = assembly_clock;
	if (setting != NULL) {
		event.setting = *setting;
	}
	if (sizeof(event) > PIPE_BUF || __real_clock_gettime(CLOCK_MONOTONIC, &event.observed_at) == -1) {
		_exit(ASSEMBLY_TIMER_CHANNEL_FAILURE);
	}
	ssize_t written;
	do {
		written = write(assembly_timer_channel(), &event, sizeof(event));
	} while (written == -1 && errno == EINTR);
	if (written != (ssize_t)sizeof(event)) {
		_exit(ASSEMBLY_TIMER_CHANNEL_FAILURE);
	}
	errno = saved_errno;
}

static assembly_timer_fault assembly_timer_fault_get(void) {
	if (!assembly_fault_loaded) {
		int saved_errno = errno;
		const char *text = getenv(ASSEMBLY_TIMER_FAULT_ENV);
		char *end;
		errno = 0;
		long fault = text == NULL ? ASSEMBLY_TIMER_NORMAL : strtol(text, &end, 10);
		if (text != NULL && (errno != 0 || *text == '\0' || *end != '\0' || fault < ASSEMBLY_TIMER_NORMAL || fault > ASSEMBLY_TIMER_LOG_DELAY)) {
			_exit(ASSEMBLY_TIMER_CHANNEL_FAILURE);
		}
		assembly_fault = (assembly_timer_fault)fault;
		assembly_fault_loaded = true;
		errno = saved_errno;
	}
	return assembly_fault;
}

static bool assembly_timer_log_matches(FILE *stream) {
	int saved_errno = errno;
	const char *expected = getenv(ASSEMBLY_TIMER_LOG_ENV);
	char filename[64];
	char target[PATH_MAX];
	int count = snprintf(filename, sizeof(filename), "/proc/self/fd/%d", fileno(stream));
	ssize_t size = count > 0 && (size_t)count < sizeof(filename) ? readlink(filename, target, sizeof(target) - 1U) : -1;
	bool result = false;
	if (size >= 0) {
		target[size] = '\0';
		result = expected != NULL && strcmp(target, expected) == 0;
	}
	errno = saved_errno;
	return result;
}

static void assembly_timer_pause(void) {
	struct timespec deadline;
	if (__real_clock_gettime(CLOCK_MONOTONIC, &deadline) == -1) {
		_exit(ASSEMBLY_TIMER_CHANNEL_FAILURE);
	}
	deadline.tv_sec += ASSEMBLY_TIMER_LOG_DELAY_MS / 1000;
	deadline.tv_nsec += (ASSEMBLY_TIMER_LOG_DELAY_MS % 1000) * 1000000L;
	if (deadline.tv_nsec >= 1000000000L) {
		deadline.tv_nsec -= 1000000000L;
		deadline.tv_sec++;
	}
	int status;
	do {
		status = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL);
	} while (status == EINTR);
	if (status != 0) {
		_exit(ASSEMBLY_TIMER_CHANNEL_FAILURE);
	}
}

/* section: functions (exported) */
int __wrap_accept4(int socket_fd, struct sockaddr *address, socklen_t *address_size, int flags) {
	int result = __real_accept4(socket_fd, address, address_size, flags);
	if (result >= 0 && assembly_socket_fd == -1) {
		assembly_socket_fd = result;
		assembly_identity_fd = result;
		assembly_timer_fd = -1;
		assembly_clock_valid = false;
		assembly_input_bytes = 0;
		assembly_expired = false;
		assembly_io_delayed = false;
	}
	return result;
}

int __wrap_clock_gettime(clockid_t clock_id, struct timespec *value) {
	int result = __real_clock_gettime(clock_id, value);
	/* Connection creation samples its assembly origin after accept and before creating its timer. */
	if (result == 0 && clock_id == CLOCK_MONOTONIC && assembly_socket_fd >= 0 && assembly_timer_fd == -1) {
		assembly_clock = *value;
		assembly_clock_valid = true;
	}
	return result;
}

int __wrap_close(int fd) {
	if (assembly_socket_fd >= 0 && fd == assembly_socket_fd && assembly_expired && assembly_timer_fault_get() == ASSEMBLY_TIMER_DROP_CLOSE) {
		assembly_timer_event_send(ASSEMBLY_TIMER_CLOSE_SUPPRESSED, fd, 0, 0, 0, NULL, 0);
		return 0;
	}
	int result = __real_close(fd);
	if (assembly_socket_fd >= 0 && fd == assembly_socket_fd && result == 0) {
		assembly_timer_event_send(ASSEMBLY_TIMER_CLOSED, fd, 0, result, errno, NULL, 0);
		assembly_socket_fd = -1;
	}
	return result;
}

int __wrap_fclose(FILE *stream) {
	if (assembly_expired && !assembly_io_delayed && assembly_timer_fault_get() == ASSEMBLY_TIMER_LOG_DELAY && assembly_timer_log_matches(stream)) {
		assembly_io_delayed = true;
		assembly_timer_event_send(ASSEMBLY_TIMER_LOG_BEGIN, fileno(stream), 0, 0, 0, NULL, 0);
		assembly_timer_pause();
		assembly_timer_event_send(ASSEMBLY_TIMER_LOG_END, fileno(stream), 0, 0, 0, NULL, 0);
	}
	return __real_fclose(stream);
}

ssize_t __wrap_read(int fd, void *buffer, size_t size) {
	ssize_t result = __real_read(fd, buffer, size);
	if (fd == assembly_timer_fd && assembly_socket_fd >= 0 && result == (ssize_t)sizeof(uint64_t)) {
		uint64_t expirations;
		memcpy(&expirations, buffer, sizeof(expirations));
		assembly_expired = true;
		assembly_timer_event_send(ASSEMBLY_TIMER_EXPIRED, fd, 0, (int)result, errno, NULL, expirations);
	}
	return result;
}

ssize_t __wrap_recv(int fd, void *buffer, size_t size, int flags) {
	ssize_t result = __real_recv(fd, buffer, size, flags);
	if (fd == assembly_socket_fd && result > 0) {
		if ((uint64_t)result > UINT64_MAX - assembly_input_bytes) {
			_exit(ASSEMBLY_TIMER_CHANNEL_FAILURE);
		}
		assembly_input_bytes += (uint64_t)result;
	}
	return result;
}

int __wrap_timerfd_create(int clock_id, int flags) {
	int result = __real_timerfd_create(clock_id, flags);
	if (result >= 0 && assembly_socket_fd >= 0 && assembly_timer_fd == -1) {
		assembly_timer_fd = result;
		assembly_timer_clock_id = clock_id;
	}
	return result;
}

int __wrap_timerfd_settime(int fd, int flags, const struct itimerspec *value, struct itimerspec *old_value) {
	if (fd != assembly_timer_fd || assembly_socket_fd < 0 || value == NULL) {
		return __real_timerfd_settime(fd, flags, value, old_value);
	}
	struct itimerspec setting = *value;
	assembly_timer_fault fault = assembly_timer_fault_get();
	if (fault == ASSEMBLY_TIMER_RELATIVE) {
		flags &= ~TFD_TIMER_ABSTIME;
	} else if (fault == ASSEMBLY_TIMER_WRONG_INITIAL && assembly_input_bytes == 0) {
		setting.it_value.tv_sec++;
	} else if (fault == ASSEMBLY_TIMER_SLIDING && assembly_input_bytes >= 2) {
		if (__real_clock_gettime(CLOCK_MONOTONIC, &setting.it_value) == -1) {
			_exit(ASSEMBLY_TIMER_CHANNEL_FAILURE);
		}
		setting.it_value.tv_sec += ASSEMBLY_TIMER_TIMEOUT_SEC;
	}
	int result = __real_timerfd_settime(fd, flags, &setting, old_value);
	assembly_timer_event_send(ASSEMBLY_TIMER_ARMED, fd, flags, result, errno, &setting, 0);
	return result;
}
