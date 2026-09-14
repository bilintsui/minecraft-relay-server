/*
 * listener_runtime_hooks.c: Test-only listener runtime hooks
 *
 * The interface intentionally lives under src/ so listener.c can declare its
 * compile-time hook seams without depending on a tests/ include path. This
 * implementation is compiled only into listener_short_runtime_daemon.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <systemd/sd-daemon.h>

/* section: headers (self) */
#include "listener_runtime_hooks.h"

/* section: defines */
/* environment */
#define LISTENER_TEST_EARLY_COLLECT_ENV	"MCRELAY_TEST_EARLY_COLLECT"
#define LISTENER_TEST_READY_FLIP_ENV	"MCRELAY_TEST_READY_FLIP"

/* marker */
#define LISTENER_TEST_EARLY_COLLECT_MARKER	"MCRELAY_TEST_EARLY_COLLECT=1"
#define LISTENER_TEST_EARLY_RELOAD_ACK_MARKER	"MCRELAY_TEST_EARLY_RELOAD_ACK=1"
#define LISTENER_TEST_READY_FLIP_BLOCKED_MARKER	"MCRELAY_TEST_RELOAD_BLOCKED=1"
#define LISTENER_TEST_READY_FLIP_HELD_MARKER	"MCRELAY_TEST_ROUTE_READY_HELD=1"
#define LISTENER_TEST_READY_FLIP_RELOAD_ACK_MARKER	"MCRELAY_TEST_READY_FLIP_RELOAD_ACK=1"
#define LISTENER_TEST_READY_FLIP_TIMER_ARM_MARKER	"MCRELAY_TEST_LATE_WAKE_ARMED=1"
#define LISTENER_TEST_READY_FLIP_TIMER_EVENT_MARKER	"MCRELAY_TEST_ROUTE_TIMER_FIRED=1"

#ifdef LISTENER_READY_FLIP_TEST
/* section: global variables */
/* Each runtime-test fixture execs a fresh daemon, so these latches are single-shot per process. */
static bool listener_test_ready_flip_armed;
static bool listener_test_ready_flip_fired;
static bool listener_test_ready_flip_held;
static bool listener_test_ready_flip_released;
#endif

/* section: functions (local) */
#if defined(LISTENER_EARLY_COLLECT_TEST) || defined(LISTENER_READY_FLIP_TEST)
static int listener_test_notify(const char *environment, const char *message) {
	if (environment == NULL || message == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (getenv(environment) == NULL) {
		return 0;
	}
	int result = sd_notify(0, message);
	if (result < 0) {
		errno = -result;
		return -1;
	}
	return 0;
}
#endif

/* section: functions (exported) */
int listener_test_early_collect_observe(bool resolver_ready, bool retired_before_collect) {
#ifdef LISTENER_EARLY_COLLECT_TEST
	if (!resolver_ready || !retired_before_collect) {
		return 0;
	}
	return listener_test_notify(LISTENER_TEST_EARLY_COLLECT_ENV, LISTENER_TEST_EARLY_COLLECT_MARKER);
#else
	(void)resolver_ready;
	(void)retired_before_collect;
	return 0;
#endif
}

int listener_test_early_collect_reload_ack(void) {
#ifdef LISTENER_EARLY_COLLECT_TEST
	return listener_test_notify(LISTENER_TEST_EARLY_COLLECT_ENV, LISTENER_TEST_EARLY_RELOAD_ACK_MARKER);
#else
	return 0;
#endif
}

int listener_test_ready_flip_hold(bool runtime_ready, bool warmup_complete, listener_test_timer_disarm_fn disarm, const void *context) {
#ifdef LISTENER_READY_FLIP_TEST
	if (getenv(LISTENER_TEST_READY_FLIP_ENV) == NULL) {
		return 0;
	}
	if (listener_test_ready_flip_held) {
		return listener_test_ready_flip_released ? 0 : 1;
	}
	if (runtime_ready || !warmup_complete) {
		return 0;
	}
	if (disarm == NULL || disarm(context) == -1) {
		if (disarm == NULL) {
			errno = EINVAL;
		}
		return -1;
	}
	listener_test_ready_flip_held = true;
	if (listener_test_notify(LISTENER_TEST_READY_FLIP_ENV, LISTENER_TEST_READY_FLIP_HELD_MARKER) == -1) {
		return -1;
	}
	return 1;
#else
	(void)runtime_ready;
	(void)warmup_complete;
	(void)disarm;
	(void)context;
	return 0;
#endif
}

int listener_test_ready_flip_release(void) {
#ifdef LISTENER_READY_FLIP_TEST
	if (getenv(LISTENER_TEST_READY_FLIP_ENV) == NULL || listener_test_ready_flip_released) {
		return 0;
	}
	listener_test_ready_flip_released = true;
	return listener_test_notify(LISTENER_TEST_READY_FLIP_ENV, LISTENER_TEST_READY_FLIP_RELOAD_ACK_MARKER);
#else
	return 0;
#endif
}

int listener_test_ready_flip_reload_blocked(void) {
#ifdef LISTENER_READY_FLIP_TEST
	return listener_test_notify(LISTENER_TEST_READY_FLIP_ENV, LISTENER_TEST_READY_FLIP_BLOCKED_MARKER);
#else
	return 0;
#endif
}

int listener_test_ready_flip_timer_arm(void) {
#ifdef LISTENER_READY_FLIP_TEST
	if (getenv(LISTENER_TEST_READY_FLIP_ENV) == NULL || listener_test_ready_flip_armed) {
		return 0;
	}
	listener_test_ready_flip_armed = true;
	return listener_test_notify(LISTENER_TEST_READY_FLIP_ENV, LISTENER_TEST_READY_FLIP_TIMER_ARM_MARKER);
#else
	return 0;
#endif
}

int listener_test_ready_flip_timer_event(void) {
#ifdef LISTENER_READY_FLIP_TEST
	if (getenv(LISTENER_TEST_READY_FLIP_ENV) == NULL || !listener_test_ready_flip_armed || listener_test_ready_flip_fired) {
		return 0;
	}
	if (listener_test_notify(LISTENER_TEST_READY_FLIP_ENV, LISTENER_TEST_READY_FLIP_TIMER_EVENT_MARKER) == -1) {
		return -1;
	}
	listener_test_ready_flip_fired = true;
	return 0;
#else
	return 0;
#endif
}

bool listener_test_ready_flip_timer_ready(void) {
#ifdef LISTENER_READY_FLIP_TEST
	if (getenv(LISTENER_TEST_READY_FLIP_ENV) == NULL) {
		return true;
	}
	return listener_test_ready_flip_fired;
#else
	return true;
#endif
}
