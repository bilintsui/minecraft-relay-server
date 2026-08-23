/*
 * resolver/helper.h: Header file of resolver/helper.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_RESOLVER_HELPER_H_INCLUDED_

#define _MRS_RESOLVER_HELPER_H_INCLUDED_

/* section: headers (library) */
#include <signal.h>
#include <sys/types.h>

/* section: types */
typedef enum {
	RESOLVER_HELPER_OK,
	RESOLVER_HELPER_BAD_ARGUMENT,
	RESOLVER_HELPER_INTERNAL,
	RESOLVER_HELPER_IO,
	RESOLVER_HELPER_PROTOCOL
} resolver_helper_status;

/* section: functions (exported) */
/* Start a named disposable fork-only helper, returning a nonblocking close-on-exec parent channel. The child retains no descriptor other than its private channel. */
int resolver_helper_process_start(const sigset_t *signal_mask, const char *process_name, pid_t *process_id, int *socket_fd);
/* Run on a caller-owned AF_UNIX SOCK_SEQPACKET channel, which may be nonblocking. A clean peer shutdown returns RESOLVER_HELPER_OK; every other terminal result makes the helper disposable. */
resolver_helper_status resolver_helper_run(int socket_fd);

#endif
