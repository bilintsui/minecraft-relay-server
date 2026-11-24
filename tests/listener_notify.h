/*
 * listener_notify.h: Startup notification wait support for listener tests
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef MCRELAY_TEST_LISTENER_NOTIFY_H
#define MCRELAY_TEST_LISTENER_NOTIFY_H

/* section: headers (library) */
#include <stddef.h>
#include <sys/types.h>

/* section: functions (exported) */
/* Reaps an exited child, stores its wait status and changes *child to -1. Timeout leaves it owned by the caller. */
ssize_t listener_test_notify_wait(int socket_fd, pid_t *child, char *message, size_t capacity, int timeout_ms, int *child_status);

#endif
