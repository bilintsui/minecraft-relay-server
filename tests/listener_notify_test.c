/*
 * listener_notify_test.c: Startup notification and early-exit regression tests
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* section: headers (project) */
#include "listener_notify.h"

/* section: defines */
#define CHECK(condition, message) \
	do { \
		if (!(condition)) { \
			fprintf(stderr, "%s (errno=%d)\n", message, errno); \
			goto cleanup; \
		} \
	} while (0)

/* section: global variables */
static volatile sig_atomic_t notify_interrupts;

/* section: functions (local) */
static void notify_test_interrupt(int signal_number) {
	(void)signal_number;
	notify_interrupts++;
}

static bool notify_test_wait(int mode) {
	bool result = false;
	int sockets[2] = { -1, -1 };
	pid_t child = -1;
	struct sigaction previous = { 0 };
	bool signal_changed = false;
	CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) == 0, "could not open notification sockets");
	child = fork();
	CHECK(child != -1, "could not fork notification child");
	if (child == 0) {
		close(sockets[0]);
		if (mode == 1) {
			_exit(23);
		}
		if (mode == 3) {
			struct timespec delay = { .tv_nsec = 500000000L };
			nanosleep(&delay, NULL);
		}
		if (mode == 0 || mode == 3 || mode == 4) {
			const char *message = mode == 4 ? "oversized-notification" : "READY=1";
			if (send(sockets[1], message, strlen(message), 0) == -1) {
				_exit(24);
			}
		}
		for (;;) {
			pause();
		}
	}
	close(sockets[1]);
	sockets[1] = -1;
	if (mode == 3) {
		struct sigaction action = { .sa_handler = notify_test_interrupt };
		sigemptyset(&action.sa_mask);
		CHECK(sigaction(SIGALRM, &action, &previous) == 0, "could not install notification interrupt");
		signal_changed = true;
		notify_interrupts = 0;
		struct itimerval timer = { .it_interval = { .tv_usec = 1000 }, .it_value = { .tv_usec = 1000 } };
		CHECK(setitimer(ITIMER_REAL, &timer, NULL) == 0, "could not start notification interrupts");
	}
	char message[16];
	int status;
	ssize_t size = listener_test_notify_wait(sockets[0], &child, message, sizeof(message), mode == 0 || mode == 1 || mode == 4 ? 1000 : 50, &status);
	if (mode == 0) {
		CHECK(size == 7 && strcmp(message, "READY=1") == 0 && child > 0, "notification did not preserve the live child");
	} else if (mode == 1) {
		CHECK(size == -1 && errno == ECHILD && child == -1 && WIFEXITED(status) && WEXITSTATUS(status) == 23, "early child exit was reported as a timeout");
	} else if (mode == 4) {
		CHECK(size == -1 && errno == EMSGSIZE && child > 0, "truncated notification was accepted");
	} else {
		CHECK(size == -1 && errno == ETIMEDOUT && child > 0, "notification timeout was reset by interrupts or lost child ownership");
		CHECK(mode != 3 || notify_interrupts > 0, "notification wait was never interrupted");
	}
	result = true;

cleanup:
	if (signal_changed) {
		sigset_t blocked, previous_mask;
		sigemptyset(&blocked);
		sigaddset(&blocked, SIGALRM);
		sigprocmask(SIG_BLOCK, &blocked, &previous_mask);
		struct itimerval timer = { 0 };
		setitimer(ITIMER_REAL, &timer, NULL);
		struct timespec immediate = { 0 };
		while (sigtimedwait(&blocked, NULL, &immediate) >= 0 || errno == EINTR) {
		}
		sigaction(SIGALRM, &previous, NULL);
		sigprocmask(SIG_SETMASK, &previous_mask, NULL);
	}
	if (child > 0) {
		kill(child, SIGKILL);
		while (waitpid(child, NULL, 0) == -1 && errno == EINTR) {
		}
	}
	if (sockets[0] != -1) {
		close(sockets[0]);
	}
	if (sockets[1] != -1) {
		close(sockets[1]);
	}
	return result;
}

/* section: functions (entry point) */
int main(void) {
	for (int mode = 0; mode <= 4; mode++) {
		if (!notify_test_wait(mode)) {
			return EXIT_FAILURE;
		}
	}
	return EXIT_SUCCESS;
}
