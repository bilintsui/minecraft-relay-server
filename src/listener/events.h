/*
 * listener/events.h: Listener event sources and ready batches
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_LISTENER_EVENTS_H_INCLUDED_

#define _MRS_LISTENER_EVENTS_H_INCLUDED_

/* section: headers (library) */
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* section: headers (project) */
#include "../resolver/hosts_watch.h"

/* section: defines */
#ifndef LISTENER_EVENT_BATCH
#define LISTENER_EVENT_BATCH	128
#endif

/* section: types */
struct listener_connection;
typedef enum {
	LISTENER_EVENT_CLIENT,
	LISTENER_EVENT_HOSTS,
	LISTENER_EVENT_LISTENER,
	LISTENER_EVENT_METRICS_TIMER,
	LISTENER_EVENT_RESOLVER,
	LISTENER_EVENT_ROUTE_TIMER,
	LISTENER_EVENT_SIGNAL,
	LISTENER_EVENT_TIMEOUT,
	LISTENER_EVENT_UPSTREAM
} listener_event_kind;
/* Registered sources must outlive their registration and every ready batch that refers to them. */
typedef struct {
	struct listener_connection *connection;
	uint64_t generation;
	listener_event_kind kind;
} listener_event_source;
typedef struct {
	int epoll_fd;
	hosts_watch *hosts_watch;
	bool hosts_watch_degraded;
	listener_event_source hosts_watch_source;
	listener_event_source listener_source;
	bool mask_blocked;
	bool metrics_timer_degraded;
	bool metrics_timer_established;
	int metrics_timer_fd;
	bool metrics_timer_registered;
	listener_event_source metrics_timer_source;
	sigset_t previous_signal_mask;
	int resolver_fd;
	listener_event_source resolver_source;
	int route_timer_fd;
	listener_event_source route_timer_source;
	int signal_fd;
	listener_event_source signal_source;
} listener_events;
typedef struct {
	uint32_t flags;
	const listener_event_source *source;
	uint64_t source_generation;
} listener_ready_event;
typedef struct {
	bool accept_ready;
	bool child_ready;
	bool hosts_watch_failed;
	bool hosts_watch_ready;
	listener_ready_event ready[LISTENER_EVENT_BATCH];
	size_t ready_count;
	bool reload;
	bool metrics_timer_failed;
	bool metrics_timer_ready;
	bool resolver_ready;
	bool route_timer_ready;
	bool stop;
} listener_requests;

/* section: functions (exported) */
int listener_events_add(const listener_events *events, int fd, uint32_t flags, const listener_event_source *source);
void listener_events_destroy(listener_events *events);
int listener_events_init(listener_events *events);
int listener_events_modify(const listener_events *events, int fd, uint32_t flags, const listener_event_source *source);
int listener_events_remove(const listener_events *events, int fd);
int listener_events_resolver_add(listener_events *events, int resolver_fd);
int listener_events_socket_add(const listener_events *events, int socket_fd);
int listener_events_wait(const listener_events *events, listener_requests *requests);

#endif
