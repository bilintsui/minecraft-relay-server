/*
 * listener_runtime_hooks.h: Header file of listener_runtime_hooks.c
 *
 * This interface lives beside listener.c because that source owns the
 * compile-time hook seams. The test-only implementation remains under tests/
 * and is linked only into listener_short_runtime_daemon.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_LISTENER_RUNTIME_HOOKS_H_INCLUDED_

#define _MRS_LISTENER_RUNTIME_HOOKS_H_INCLUDED_

/* section: headers (library) */
#include <stdbool.h>

/* section: types */
typedef int (*listener_test_timer_disarm_fn)(const void *context);

/* section: functions (exported) */
int listener_test_early_collect_observe(bool resolver_ready, bool retired_before_collect);
int listener_test_early_collect_reload_ack(void);
int listener_test_ready_flip_hold(bool runtime_ready, bool warmup_complete, listener_test_timer_disarm_fn disarm, const void *context);
int listener_test_ready_flip_release(void);
int listener_test_ready_flip_reload_blocked(void);
int listener_test_ready_flip_timer_arm(void);
int listener_test_ready_flip_timer_event(void);
bool listener_test_ready_flip_timer_ready(void);

#endif
