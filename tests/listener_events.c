/*
 * listener_events.c: Listener event ownership and teardown
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/wait.h>
#include <unistd.h>

/* section: headers (project) */
#include "listener/events.h"

/* section: defines */
#define CHECK(condition) \
	do { \
		if (!(condition)) { \
			fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
			return false; \
		} \
	} while (0)

/* section: global variables */
static bool fail_epoll_create;

/* section: functions (local) */
static bool blocked(int signo) {
	sigset_t mask;
	return sigprocmask(SIG_SETMASK, NULL, &mask) == 0 && sigismember(&mask, signo) == 1;
}

static bool child_dispose(listener_events *events) {
	int owned[] = { events->epoll_fd, events->signal_fd, events->route_timer_fd, events->metrics_timer_fd, hosts_watch_descriptor(events->hosts_watch) };
	int borrowed = events->resolver_fd;
	listener_events_dispose_in_child(events);
	for (size_t index = 0; index < sizeof(owned) / sizeof(owned[0]); index++) {
		CHECK(fcntl(owned[index], F_GETFD) == -1 && errno == EBADF);
	}
	CHECK(fcntl(borrowed, F_GETFD) != -1 && blocked(SIGTERM));
	CHECK(sigismember(&events->previous_signal_mask, SIGTERM) == 0);
	return true;
}

static bool failed_init(void) {
	listener_events events;
	fail_epoll_create = true;
	CHECK(listener_events_init(&events) == -1 && errno == EMFILE);
	fail_epoll_create = false;
	CHECK(events.signal_fd == -1 && events.epoll_fd == -1 && !events.mask_blocked && !blocked(SIGTERM));
	listener_events_destroy(&events);
	return true;
}

static bool lifecycle(void) {
	listener_events events;
	CHECK(listener_events_init(&events) == 0 && blocked(SIGTERM));
	int borrowed = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	CHECK(borrowed != -1 && listener_events_resolver_add(&events, borrowed) == 0);
	CHECK(listener_events_hosts_watch_establish(&events, "/etc/hosts", NULL) == 0);
	CHECK(listener_events_metrics_timer_set(&events, 3600) == 0);
	pid_t child = fork();
	CHECK(child != -1);
	if (child == 0) {
		_exit(child_dispose(&events) ? EXIT_SUCCESS : EXIT_FAILURE);
	}
	int status;
	CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS);
	CHECK(eventfd_write(borrowed, 1) == 0);
	listener_requests requests;
	CHECK(listener_events_wait(&events, &requests) == 0 && requests.resolver_ready);

	int released = events.epoll_fd;
	listener_events_destroy(&events);
	CHECK(!blocked(SIGTERM) && !events.mask_blocked && events.epoll_fd == -1 && events.signal_fd == -1 && events.route_timer_fd == -1);
	CHECK(events.hosts_watch == NULL && events.resolver_fd == -1 && events.metrics_timer_fd == -1 && !events.metrics_timer_registered && !events.metrics_timer_established);
	CHECK(dup2(borrowed, released) == released);
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR2);
	CHECK(sigprocmask(SIG_BLOCK, &mask, NULL) == 0);
	listener_events_destroy(&events);
	CHECK(blocked(SIGUSR2) && fcntl(released, F_GETFD) != -1 && fcntl(borrowed, F_GETFD) != -1);
	close(released);
	close(borrowed);
	return true;
}

/* section: functions (exported) */
int __real_epoll_create1(int flags);

int __wrap_epoll_create1(int flags) {
	if (fail_epoll_create) {
		errno = EMFILE;
		return -1;
	}
	return __real_epoll_create1(flags);
}

/* section: functions (entry point) */
int main(void) {
	sigset_t mask;
	sigemptyset(&mask);
	if (sigprocmask(SIG_SETMASK, &mask, NULL) == -1) {
		return EXIT_FAILURE;
	}
	listener_events_destroy(NULL);
	return failed_init() && lifecycle() ? EXIT_SUCCESS : EXIT_FAILURE;
}
