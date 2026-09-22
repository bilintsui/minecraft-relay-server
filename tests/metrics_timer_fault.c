/*
 * metrics_timer_fault.c: Metrics timer fault injection for listener runtime tests
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <unistd.h>

/* section: global variables */
static int metrics_timer_fd = -1;
static bool metrics_timer_read_injected;
static bool metrics_timer_set_injected;

/* section: functions (exported) */
ssize_t __real_read(int fd, void *buffer, size_t size);
int __real_timerfd_settime(int fd, int flags, const struct itimerspec *new_value, struct itimerspec *old_value);

ssize_t __wrap_read(int fd, void *buffer, size_t size) {
	if (fd == metrics_timer_fd && !metrics_timer_read_injected) {
		const char *mode = getenv("MCRELAY_TEST_METRICS_TIMER_READ");
		const char *reload_trigger = getenv("MCRELAY_TEST_METRICS_RELOAD_TRIGGER");
		if (mode != NULL && strncmp(mode, "reload-", strlen("reload-")) == 0 && reload_trigger != NULL && access(reload_trigger, F_OK) == 0) {
			metrics_timer_read_injected = true;
			if (kill(getpid(), SIGUSR1) == -1) {
				return -1;
			}
			errno = EAGAIN;
			return -1;
		}
		if (mode != NULL && strcmp(mode, "eintr") == 0) {
			metrics_timer_read_injected = true;
			errno = EINTR;
			return -1;
		}
		if (mode != NULL && strcmp(mode, "eagain") == 0) {
			metrics_timer_read_injected = true;
			errno = EAGAIN;
			return -1;
		}
		if (mode != NULL && strcmp(mode, "eio") == 0) {
			metrics_timer_read_injected = true;
			errno = EIO;
			return -1;
		}
	}
	return __real_read(fd, buffer, size);
}

int __wrap_timerfd_settime(int fd, int flags, const struct itimerspec *new_value, struct itimerspec *old_value) {
	if (flags == 0 && new_value != NULL && new_value->it_interval.tv_sec > 0) {
		metrics_timer_fd = fd;
		if (!metrics_timer_set_injected && getenv("MCRELAY_TEST_METRICS_TIMER_ARM_FAIL") != NULL) {
			metrics_timer_set_injected = true;
			errno = EIO;
			return -1;
		}
	}
	return __real_timerfd_settime(fd, flags, new_value, old_value);
}
