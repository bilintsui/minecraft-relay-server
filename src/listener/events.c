/*
 * listener/events.c: Listener event collection and signal handling
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* section: headers (project) */
#include "../resolver/hosts_watch.h"

/* section: headers (self) */
#include "events.h"

/* section: functions (local) */
static void listener_events_fd_close(int *fd) {
	if (*fd != -1) {
		close(*fd);
		*fd = -1;
	}
}

static void listener_events_descriptors_close(listener_events *events) {
	listener_events_fd_close(&events->epoll_fd);
	hosts_watch_destroy(events->hosts_watch);
	events->hosts_watch = NULL;
	events->hosts_watch_degraded = false;
	listener_events_fd_close(&events->metrics_timer_fd);
	events->metrics_timer_registered = false;
	events->metrics_timer_established = false;
	events->metrics_timer_degraded = false;
	listener_events_fd_close(&events->signal_fd);
	listener_events_fd_close(&events->route_timer_fd);
	events->resolver_fd = -1;
}

static void listener_events_metrics_timer_fail(listener_events *events, int error) {
	if (events->metrics_timer_fd != -1) {
		if (events->metrics_timer_registered) {
			(void)listener_events_remove(events, events->metrics_timer_fd);
			events->metrics_timer_registered = false;
		}
		struct itimerspec disarmed;
		memset(&disarmed, 0, sizeof(disarmed));
		(void)timerfd_settime(events->metrics_timer_fd, 0, &disarmed, NULL);
		if (events->metrics_timer_established) {
			events->metrics_timer_degraded = true;
		} else {
			close(events->metrics_timer_fd);
			events->metrics_timer_fd = -1;
		}
	}
	errno = error;
}

static int listener_signals_read(int signal_fd, listener_requests *requests) {
	while (1) {
		struct signalfd_siginfo signal_info;
		ssize_t bytes = read(signal_fd, &signal_info, sizeof(signal_info));
		if (bytes == (ssize_t)sizeof(signal_info)) {
			switch (signal_info.ssi_signo) {
				case SIGCHLD:
					requests->child_ready = true;
					break;
				case SIGINT:
				case SIGTERM:
					requests->stop = true;
					break;
				case SIGUSR1:
					requests->reload = true;
					break;
			}
			continue;
		}
		if (bytes == -1 && errno == EINTR) {
			continue;
		}
		if (bytes == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return 0;
		}
		if (bytes != -1) {
			errno = EIO;
		}
		return -1;
	}
}

/* section: functions (exported) */
int listener_events_add(const listener_events *events, int fd, uint32_t flags, const listener_event_source *source) {
	struct epoll_event event;
	memset(&event, 0, sizeof(event));
	event.events = flags;
	event.data.ptr = (void *)source;
	return epoll_ctl(events->epoll_fd, EPOLL_CTL_ADD, fd, &event);
}

void listener_events_destroy(listener_events *events) {
	if (events == NULL) {
		return;
	}
	listener_events_descriptors_close(events);
	if (events->mask_blocked) {
		sigprocmask(SIG_SETMASK, &events->previous_signal_mask, NULL);
		events->mask_blocked = false;
	}
}

void listener_events_dispose_in_child(listener_events *events) {
	listener_events_descriptors_close(events);
	events->mask_blocked = false;
}

bool listener_events_hosts_watch_active(const listener_events *events) {
	return events->hosts_watch != NULL && !events->hosts_watch_degraded;
}

void listener_events_hosts_watch_disable(listener_events *events) {
	if (events->hosts_watch != NULL) {
		(void)listener_events_remove(events, hosts_watch_descriptor(events->hosts_watch));
		hosts_watch_destroy(events->hosts_watch);
		events->hosts_watch = NULL;
	}
	events->hosts_watch_degraded = true;
}

int listener_events_hosts_watch_establish(listener_events *events, const char *filename, bool *overlap_changed) {
	hosts_watch *candidate = NULL;
	if (overlap_changed != NULL) {
		*overlap_changed = false;
	}
	if (events == NULL) {
		errno = EINVAL;
		return -1;
	}
	hosts_watch_create_status status = hosts_watch_create(filename, &candidate);
	if (status != HOSTS_WATCH_CREATE_OK) {
		events->hosts_watch_degraded = true;
		if (status == HOSTS_WATCH_CREATE_BAD_ARGUMENT) {
			errno = EINVAL;
		} else if (status == HOSTS_WATCH_CREATE_MEMORY) {
			errno = ENOMEM;
		}
		return -1;
	}
	if (listener_events_add(events, hosts_watch_descriptor(candidate), EPOLLIN, &events->hosts_watch_source) == -1) {
		int saved_errno = errno;
		hosts_watch_destroy(candidate);
		events->hosts_watch_degraded = true;
		errno = saved_errno;
		return -1;
	}
	bool recovered = events->hosts_watch_degraded;
	hosts_watch *previous = events->hosts_watch;
	events->hosts_watch = candidate;
	events->hosts_watch_degraded = false;
	if (previous != NULL) {
		hosts_watch_events overlap_events;
		hosts_watch_read_status overlap_status = hosts_watch_read(previous, &overlap_events);
		if (overlap_changed != NULL) {
			*overlap_changed = overlap_status != HOSTS_WATCH_READ_OK || overlap_events.changed;
		}
		(void)listener_events_remove(events, hosts_watch_descriptor(previous));
		hosts_watch_destroy(previous);
	}
	return recovered ? 1 : 0;
}

hosts_watch_read_status listener_events_hosts_watch_read(const listener_events *events, hosts_watch_events *changes) {
	return hosts_watch_read(events->hosts_watch, changes);
}

int listener_events_init(listener_events *events) {
	int saved_errno;
	memset(events, 0, sizeof(*events));
	events->epoll_fd = -1;
	events->metrics_timer_fd = -1;
	events->resolver_fd = -1;
	events->route_timer_fd = -1;
	events->signal_fd = -1;
	events->hosts_watch_source.kind = LISTENER_EVENT_HOSTS;
	events->listener_source.kind = LISTENER_EVENT_LISTENER;
	events->metrics_timer_source.kind = LISTENER_EVENT_METRICS_TIMER;
	events->resolver_source.kind = LISTENER_EVENT_RESOLVER;
	events->route_timer_source.kind = LISTENER_EVENT_ROUTE_TIMER;
	events->signal_source.kind = LISTENER_EVENT_SIGNAL;
	struct sigaction child_action = { 0 };
	sigemptyset(&child_action.sa_mask);
	child_action.sa_flags = SA_NOCLDSTOP;
	child_action.sa_handler = SIG_DFL;
	if (sigaction(SIGCHLD, &child_action, NULL) == -1) {
		return -1;
	}
	sigset_t signal_mask;
	sigemptyset(&signal_mask);
	sigaddset(&signal_mask, SIGCHLD);
	sigaddset(&signal_mask, SIGINT);
	sigaddset(&signal_mask, SIGTERM);
	sigaddset(&signal_mask, SIGUSR1);
	if (sigprocmask(SIG_BLOCK, &signal_mask, &events->previous_signal_mask) == -1) {
		return -1;
	}
	events->mask_blocked = true;
	events->signal_fd = signalfd(-1, &signal_mask, SFD_NONBLOCK | SFD_CLOEXEC);
	if (events->signal_fd == -1) {
		goto fail;
	}
	events->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (events->epoll_fd == -1) {
		goto fail;
	}
	if (listener_events_add(events, events->signal_fd, EPOLLIN, &events->signal_source) == -1) {
		goto fail;
	}
	events->route_timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (events->route_timer_fd == -1) {
		goto fail;
	}
	if (listener_events_add(events, events->route_timer_fd, EPOLLIN, &events->route_timer_source) == -1) {
		goto fail;
	}
	return 0;
fail:
	saved_errno = errno;
	listener_events_destroy(events);
	errno = saved_errno;
	return -1;
}

bool listener_events_metrics_timer_needs_retry(const listener_events *events) {
	return events->metrics_timer_fd == -1 && !events->metrics_timer_degraded;
}

listener_metrics_timer_read_status listener_events_metrics_timer_read(listener_events *events, bool event_failed, uint64_t *expirations) {
	if (event_failed) {
		listener_events_metrics_timer_fail(events, EIO);
		return LISTENER_METRICS_TIMER_FAILED;
	}
	ssize_t size;
	do {
		size = read(events->metrics_timer_fd, expirations, sizeof(*expirations));
	} while (size == -1 && errno == EINTR);
	if (size == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		return LISTENER_METRICS_TIMER_EMPTY;
	}
	if (size != (ssize_t)sizeof(*expirations)) {
		int failure_errno = size == -1 ? errno : EIO;
		listener_events_metrics_timer_fail(events, failure_errno);
		return LISTENER_METRICS_TIMER_FAILED;
	}
	return LISTENER_METRICS_TIMER_EXPIRED;
}

int listener_events_metrics_timer_set(listener_events *events, uint32_t interval) {
	if (events->metrics_timer_degraded || (interval == 0 && events->metrics_timer_fd == -1)) {
		return 0;
	}
	if (events->metrics_timer_fd == -1) {
		events->metrics_timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
		if (events->metrics_timer_fd == -1 || listener_events_add(events, events->metrics_timer_fd, EPOLLIN, &events->metrics_timer_source) == -1) {
			listener_events_metrics_timer_fail(events, errno);
			return -1;
		}
		events->metrics_timer_registered = true;
	}
	struct itimerspec timer = {
		.it_interval = { .tv_sec = interval },
		.it_value = { .tv_sec = interval }
	};
	if (timerfd_settime(events->metrics_timer_fd, 0, &timer, NULL) == -1) {
		listener_events_metrics_timer_fail(events, errno);
		return -1;
	}
	if (interval != 0) {
		events->metrics_timer_established = true;
	}
	return 0;
}

int listener_events_modify(const listener_events *events, int fd, uint32_t flags, const listener_event_source *source) {
	struct epoll_event event;
	memset(&event, 0, sizeof(event));
	event.events = flags;
	event.data.ptr = (void *)source;
	return epoll_ctl(events->epoll_fd, EPOLL_CTL_MOD, fd, &event);
}

int listener_events_remove(const listener_events *events, int fd) {
	return epoll_ctl(events->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
}

int listener_events_resolver_add(listener_events *events, int resolver_fd) {
	if (events == NULL || resolver_fd < 0 || events->resolver_fd != -1) {
		errno = EINVAL;
		return -1;
	}
	if (listener_events_add(events, resolver_fd, EPOLLIN, &events->resolver_source) == -1) {
		return -1;
	}
	events->resolver_fd = resolver_fd;
	return 0;
}

int listener_events_route_timer_drain(const listener_events *events) {
	uint64_t expirations;
	ssize_t bytes;
	do {
		bytes = read(events->route_timer_fd, &expirations, sizeof(expirations));
	} while (bytes == -1 && errno == EINTR);
	if (bytes == (ssize_t)sizeof(expirations)) {
		return 0;
	}
	if (bytes != -1) {
		errno = EIO;
	}
	return -1;
}

int listener_events_route_timer_set(const listener_events *events, const struct itimerspec *timer) {
	return timerfd_settime(events->route_timer_fd, TFD_TIMER_ABSTIME, timer, NULL);
}

int listener_events_socket_add(const listener_events *events, int socket_fd) {
	int socket_flags = fcntl(socket_fd, F_GETFL);
	if (socket_flags == -1 || fcntl(socket_fd, F_SETFL, socket_flags | O_NONBLOCK) == -1) {
		return -1;
	}
	return listener_events_add(events, socket_fd, EPOLLIN, &events->listener_source);
}

int listener_events_wait(const listener_events *events, listener_requests *requests) {
	struct epoll_event ready_events[LISTENER_EVENT_BATCH];
	memset(requests, 0, sizeof(*requests));
	int ready_count;
	do {
		ready_count = epoll_wait(events->epoll_fd, ready_events, LISTENER_EVENT_BATCH, -1);
	} while (ready_count == -1 && errno == EINTR);
	if (ready_count == -1) {
		return -1;
	}
	for (int i = 0; i < ready_count; i++) {
		uint32_t event_flags = ready_events[i].events;
		const listener_event_source *source = ready_events[i].data.ptr;
		if (source == NULL) {
			errno = EIO;
			return -1;
		}
		switch (source->kind) {
		case LISTENER_EVENT_HOSTS:
			if (source != &events->hosts_watch_source || events->hosts_watch == NULL) {
				errno = EIO;
				return -1;
			}
			if (event_flags & (EPOLLERR | EPOLLHUP)) {
				requests->hosts_watch_failed = true;
			}
			if (event_flags & EPOLLIN) {
				requests->hosts_watch_ready = true;
			}
			break;
		case LISTENER_EVENT_SIGNAL:
			if (source != &events->signal_source) {
				errno = EIO;
				return -1;
			}
			if ((event_flags & EPOLLIN) && listener_signals_read(events->signal_fd, requests) == -1) {
				return -1;
			}
			if (event_flags & (EPOLLERR | EPOLLHUP)) {
				errno = EIO;
				return -1;
			}
			break;
		case LISTENER_EVENT_LISTENER:
			if (source != &events->listener_source) {
				errno = EIO;
				return -1;
			}
			if (event_flags & (EPOLLERR | EPOLLHUP)) {
				errno = EIO;
				return -1;
			}
			if (event_flags & EPOLLIN) {
				requests->accept_ready = true;
			}
			break;
		case LISTENER_EVENT_METRICS_TIMER:
			if (source != &events->metrics_timer_source || events->metrics_timer_fd == -1 || !events->metrics_timer_registered) {
				errno = EIO;
				return -1;
			}
			if (event_flags & (EPOLLERR | EPOLLHUP)) {
				requests->metrics_timer_failed = true;
			}
			if (event_flags & EPOLLIN) {
				requests->metrics_timer_ready = true;
			}
			break;
		case LISTENER_EVENT_RESOLVER:
			if (source != &events->resolver_source || events->resolver_fd == -1) {
				errno = EIO;
				return -1;
			}
			if (event_flags & (EPOLLERR | EPOLLHUP)) {
				errno = EIO;
				return -1;
			}
			if (event_flags & EPOLLIN) {
				requests->resolver_ready = true;
			}
			break;
		case LISTENER_EVENT_ROUTE_TIMER:
			if (source != &events->route_timer_source) {
				errno = EIO;
				return -1;
			}
			if (event_flags & (EPOLLERR | EPOLLHUP)) {
				errno = EIO;
				return -1;
			}
			if (event_flags & EPOLLIN) {
				requests->route_timer_ready = true;
			}
			break;
		case LISTENER_EVENT_CLIENT:
		case LISTENER_EVENT_TIMEOUT:
		case LISTENER_EVENT_UPSTREAM:
			if (source->connection == NULL || requests->ready_count >= sizeof(requests->ready) / sizeof(requests->ready[0])) {
				errno = EOVERFLOW;
				return -1;
			}
			requests->ready[requests->ready_count].flags = event_flags;
			requests->ready[requests->ready_count].source = source;
			requests->ready[requests->ready_count].source_generation = source->generation;
			requests->ready_count++;
			break;
		default:
			errno = EIO;
			return -1;
		}
	}
	return 0;
}
