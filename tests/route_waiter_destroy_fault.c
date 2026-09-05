/*
 * route_waiter_destroy_fault.c: Deterministic route-release failure injection
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* section: headers (project) */
#include "route/waiter.h"

/* section: global variables */
static bool route_waiter_destroy_fault_injected;

/* section: functions (local) */
static route_waiter_destroy_status route_waiter_destroy_fault_status(const char *text) {
	if (text == NULL) {
		return ROUTE_WAITER_DESTROY_BAD_ARGUMENT;
	}
	if (strcmp(text, "IO") == 0) {
		return ROUTE_WAITER_DESTROY_IO;
	}
	if (strcmp(text, "TIME") == 0) {
		return ROUTE_WAITER_DESTROY_TIME;
	}
	return ROUTE_WAITER_DESTROY_BAD_ARGUMENT;
}

/* section: functions (exported) */
route_waiter_destroy_status __real_route_waiter_destroy(route_waiter *waiter, resolver_supervisor *supervisor, const struct timespec *now);

route_waiter_destroy_status __wrap_route_waiter_destroy(route_waiter *waiter, resolver_supervisor *supervisor, const struct timespec *now) {
	const char *status_text = getenv("MCRELAY_TEST_ROUTE_DESTROY_FAULT_STATUS");
	const char *trigger_filename = getenv("MCRELAY_TEST_ROUTE_DESTROY_FAULT_TRIGGER");
	bool inject = !route_waiter_destroy_fault_injected && status_text != NULL && trigger_filename != NULL && waiter != NULL && access(trigger_filename, F_OK) == 0;
	route_waiter_destroy_status status = __real_route_waiter_destroy(waiter, supervisor, now);
	if (inject) {
		route_waiter_destroy_fault_injected = true;
		return route_waiter_destroy_fault_status(status_text);
	}
	return status;
}
