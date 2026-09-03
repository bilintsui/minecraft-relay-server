/*
 * route/waiter.h: Header file of route/waiter.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_ROUTE_WAITER_H_INCLUDED_

#define _MRS_ROUTE_WAITER_H_INCLUDED_

/* section: headers (library) */
#include <stdbool.h>
#include <time.h>

/* section: headers (project) */
#include "../protocol/proxy.h"
#include "../resolver/supervisor.h"
#include "endpoint.h"
#include "generation.h"

/* section: defines */
/* connection route deadline */
#ifndef LISTENER_ROUTE_WAIT_TIMEOUT_SEC
#define LISTENER_ROUTE_WAIT_TIMEOUT_SEC	10
#endif

/* section: types */
typedef struct route_waiter route_waiter;
typedef enum {
	ROUTE_WAITER_COMPLETION_OK,
	ROUTE_WAITER_COMPLETION_IGNORED,
	ROUTE_WAITER_COMPLETION_BAD_ARGUMENT,
	ROUTE_WAITER_COMPLETION_MEMORY
} route_waiter_completion_status;
typedef enum {
	ROUTE_WAITER_CREATE_OK,
	ROUTE_WAITER_CREATE_BAD_ARGUMENT,
	ROUTE_WAITER_CREATE_LIMIT,
	ROUTE_WAITER_CREATE_MEMORY,
	ROUTE_WAITER_CREATE_TIME
} route_waiter_create_status;
typedef enum {
	ROUTE_WAITER_DESTROY_OK,
	ROUTE_WAITER_DESTROY_BAD_ARGUMENT,
	ROUTE_WAITER_DESTROY_IO,
	ROUTE_WAITER_DESTROY_TIME
} route_waiter_destroy_status;
typedef enum {
	ROUTE_WAITER_PENDING,
	ROUTE_WAITER_READY,
	ROUTE_WAITER_BAD_ARGUMENT,
	ROUTE_WAITER_CONTRADICTORY,
	ROUTE_WAITER_IO,
	ROUTE_WAITER_LIMIT,
	ROUTE_WAITER_MEMORY,
	ROUTE_WAITER_NO_ROUTE,
	ROUTE_WAITER_SERVICE_UNAVAILABLE,
	ROUTE_WAITER_TIME,
	ROUTE_WAITER_TIMEOUT,
	ROUTE_WAITER_UNAVAILABLE
} route_waiter_status;

/* section: functions (exported) */
/* Call only after every live generation coordinator has observed the completion. This function borrows the completion and copies any accepted transient payload. */
route_waiter_completion_status route_waiter_completion_observe(route_waiter *waiter, const resolver_supervisor_completion *completion);
/* The waiter retains generation until destruction. */
route_waiter_create_status route_waiter_create(route_generation *generation, const char *vhost, const p_proxy *inbound_proxy, const struct timespec *now,
	route_waiter **result);
bool route_waiter_deadline(const route_waiter *waiter, struct timespec *result);
/* Destroy pending waiters before their supervisor. SATISFIED release outcomes are normal. */
route_waiter_destroy_status route_waiter_destroy(route_waiter *waiter, resolver_supervisor *supervisor, const struct timespec *now);
/* Dispose a waiter after its supervisor has gone away, releasing only local ownership. */
void route_waiter_dispose(route_waiter *waiter);
route_waiter_status route_waiter_progress(route_waiter *waiter, resolver_supervisor *supervisor, const struct timespec *now);
/* A successful take transfers a fully self-contained value snapshot and may occur only once. */
bool route_waiter_snapshot_take(route_waiter *waiter, route_endpoint_snapshot *result);

#endif
