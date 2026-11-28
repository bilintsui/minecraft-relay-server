/*
 * listener/connection.h: Listener-owned connection state
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_LISTENER_CONNECTION_H_INCLUDED_

#define _MRS_LISTENER_CONNECTION_H_INCLUDED_

/* section: headers (library) */
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

/* section: headers (project) */
#include "../connection/setup.h"
#include "../connection/setup_short.h"
#include "../network.h"
#include "../protocol/proxy.h"
#include "../resolver/supervisor.h"
#include "../route/endpoint.h"
#include "../route/generation.h"
#include "../route/waiter.h"
#include "events.h"
#include "metrics.h"

/* section: types */
typedef struct {
	size_t capacity;
	uint8_t *data;
	size_t offset;
	size_t size;
} listener_connection_buffer;
typedef enum {
	LISTENER_CONNECTION_ABORT,
	LISTENER_CONNECTION_CLOSED,
	LISTENER_CONNECTION_FATAL,
	LISTENER_CONNECTION_PENDING,
	LISTENER_CONNECTION_READY
} listener_connection_progress;
typedef enum {
	LISTENER_CONNECTION_ROUTE_INVALID,
	LISTENER_CONNECTION_ROUTE_SHORT_LOCAL,
	LISTENER_CONNECTION_ROUTE_SHORT_WAIT,
	LISTENER_CONNECTION_ROUTE_WORKER_BYPASS,
	LISTENER_CONNECTION_ROUTE_WORKER_WAIT
} listener_connection_route;
typedef enum {
	LISTENER_CONNECTION_INITIAL,
	LISTENER_CONNECTION_ROUTE_WAITING,
	LISTENER_CONNECTION_SHORT_CONNECTING,
	LISTENER_CONNECTION_SHORT_RELAYING,
	LISTENER_CONNECTION_SHORT_RESPONDING,
	LISTENER_CONNECTION_WORKER_REFUSING
} listener_connection_state;
typedef enum {
	LISTENER_CONNECTION_TIMER_ASSEMBLY,
	LISTENER_CONNECTION_TIMER_GRACE,
	LISTENER_CONNECTION_TIMER_ROUTE,
	LISTENER_CONNECTION_TIMER_SHORT_CONNECT,
	LISTENER_CONNECTION_TIMER_SHORT_IDLE,
	LISTENER_CONNECTION_TIMER_SHORT_LIFETIME,
	LISTENER_CONNECTION_TIMER_WORKER_REFUSAL
} listener_connection_timer;
typedef struct listener_connection {
	net_addr peer_address;
	in_port_t peer_port;
	struct timespec assembly_deadline;
	listener_connection_buffer client_buffer;
	uint32_t client_events;
	bool client_read_closed;
	bool client_read_paused;
	listener_event_source client_source;
	bool client_registered;
	bool client_write_closed;
	bool closing;
	listener_connection_route dispatch;
	route_endpoint_snapshot endpoint;
	route_generation *generation;
	uint8_t inbound[BUFSIZ];
	size_t inbound_size;
	p_proxy inbound_proxy;
	bool prefix_checked;
	uint16_t proxy_remaining;
	connection_proxy_origin proxy_origin;
	struct timespec lifetime_deadline;
	struct listener_connection *next;
	size_t request_offset;
	listener_metrics_route_request route_metrics;
	connection_setup_short_plan short_plan;
	int socket_fd;
	listener_connection_state state;
	int timer_fd;
	struct timespec timer_deadline;
	listener_event_source timer_source;
	listener_connection_timer timer;
	listener_connection_buffer upstream_buffer;
	bool upstream_buffer_owned;
	uint32_t upstream_events;
	int upstream_fd;
	bool upstream_read_closed;
	bool upstream_read_paused;
	bool upstream_registered;
	listener_event_source upstream_source;
	bool upstream_write_closed;
	route_waiter *waiter;
	route_waiter_status waiter_status;
	char vhost[ROUTE_ENDPOINT_TEXT_SIZE];
} listener_connection;

/* section: functions (exported) */
net_addrbundle listener_connection_client(const listener_connection *connection);
/* Takes ownership of the accepted socket and retained route generation, including on failure. */
listener_connection *listener_connection_create(int client_fd, const net_addr *peer_address, in_port_t peer_port, const listener_events *events, route_generation *generation);
bool listener_connection_destroy(listener_connection **connections, listener_connection *target, const listener_events *events, listener_metrics_state *metrics,
	listener_metrics_outcome unsettled_outcome, resolver_supervisor *supervisor, const struct timespec *now);
void listener_connection_finish(listener_connection *connection, listener_connection_progress progress, const char *log_filename, uint8_t log_level);
int listener_connection_interests_update(listener_connection *connection, const listener_events *events);
size_t listener_connection_limit(void);
bool listener_connection_route_release(listener_connection *connection, listener_metrics_state *metrics, resolver_supervisor *supervisor, const struct timespec *now);
bool listener_connection_snapshot_prepare(const listener_connection *connection, const char *working_directory, connection_setup_snapshot *result);
int listener_connection_timer_arm(listener_connection *connection, listener_connection_timer timer);
int listener_connection_timer_arm_short(listener_connection *connection, listener_connection_timer timer, const struct timespec *now, uint64_t seconds);
int listener_connection_timer_set(listener_connection *connection, listener_connection_timer timer, const struct timespec *expiration);
void listener_connections_close_except(listener_connection *connections, const listener_connection *except);
bool listener_connections_destroy_closed(listener_connection **connections, const listener_events *events, listener_metrics_state *metrics,
	resolver_supervisor *supervisor, const struct timespec *now, size_t *destroyed_count);

#endif
